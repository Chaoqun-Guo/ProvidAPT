// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package pipeline implements the event processing pipeline for
// ProvidAPT v2 with causality-preserving data reduction.
package edgereduce

import (
	"container/list"
	"fmt"
	"log"
	"sync"
	"time"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// Constants

// MergeWindow is the time window for edge deduplication.
const MergeWindow = 5 * time.Second

// NeverMergeEvents are event types that must never be merged.
var neverMergeTypes = map[uint32]bool{
	2:  true, // EV_PROCESS_EXEC
	20: true, // EV_NET_CONNECT
	21: true, // EV_NET_ACCEPT
	1:  true, // EV_PROCESS_FORK
}

// CachedEdge

// CachedEdge represents an edge in the merge cache.
type CachedEdge struct {
	Source    string
	Target    string
	Relation  string
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time

	// list element for LRU eviction
	element *list.Element
}

// Key returns the deduplication key.
func (ce *CachedEdge) Key() string {
	return fmt.Sprintf("%s|%s|%s", ce.Source, ce.Target, ce.Relation)
}

// EdgeReducer

// EdgeReducer implements sliding-window edge deduplication.
// It maintains an LRU cache of recently seen edges and merges
// duplicates within a 5-second window.
type EdgeReducer struct {
	mu      sync.Mutex
	cache   map[string]*CachedEdge
	lru     *list.List
	maxSize int
	window  time.Duration
	stats   ReducerStats

	// Flush callback: called for each edge that needs persistence.
	flushFn func(*CachedEdge) error
}

// ReducerStats tracks performance.
type ReducerStats struct {
	TotalEdges     int64
	MergedEdges    int64
	FlushedEdges   int64
	CacheEvictions int64
}

// NewEdgeReducer creates an edge reducer.
//
//	maxSize: maximum number of cached edges (default 10000)
//	window:  merge window duration (default 5s)
//	flushFn: called when an edge is flushed/evicted
func NewEdgeReducer(maxSize int, window time.Duration, flushFn func(*CachedEdge) error) *EdgeReducer {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if window <= 0 {
		window = MergeWindow
	}
	return &EdgeReducer{
		cache:   make(map[string]*CachedEdge),
		lru:     list.New(),
		maxSize: maxSize,
		window:  window,
		flushFn: flushFn,
	}
}

// Core logic

// Ingest processes an event and decides whether to merge or persist.
//
// Returns:
//   - cachedEdge: the (possibly merged) edge
//   - merged: true if this event was merged (no persistence needed)
//   - err: error if any
func (er *EdgeReducer) Ingest(evt *pb.Event) (*CachedEdge, bool, error) {
	er.mu.Lock()
	defer er.mu.Unlock()

	er.stats.TotalEdges++

	// Never merge critical events
	if neverMergeTypes[evt.Type] {
		log.Printf("[reducer] critical event type=%d -?no merge", evt.Type)
		// For critical events, still pass through but force flush
		edge := &CachedEdge{
			Source:   fmt.Sprintf("p:%d", evt.Pid),
			Target:   er.targetFor(evt),
			Relation: er.relationFor(evt),
			Count:    1,
			LastSeen: time.Unix(0, int64(evt.TimestampNs)),
		}
		return edge, false, nil
	}

	// Build candidate edge
	source := fmt.Sprintf("p:%d", evt.Pid)
	target := er.targetFor(evt)
	relation := er.relationFor(evt)
	now := time.Unix(0, int64(evt.TimestampNs))

	key := fmt.Sprintf("%s|%s|%s", source, target, relation)

	// Check cache
	if existing, ok := er.cache[key]; ok {
		// Check time window
		if now.Sub(existing.LastSeen) < er.window {
			// Merge: increment count, update timestamp
			existing.Count++
			existing.LastSeen = now

			// Move to front of LRU
			er.lru.MoveToFront(existing.element)

			er.stats.MergedEdges++
			return existing, true, nil
		}
		// Outside window: flush old, create new
		if err := er.flushLocked(existing); err != nil {
			return nil, false, err
		}
	}

	// Create new cache entry
	ce := &CachedEdge{
		Source:    source,
		Target:    target,
		Relation:  relation,
		Count:     1,
		FirstSeen: now,
		LastSeen:  now,
	}

	// Evict LRU if at capacity
	if er.lru.Len() >= er.maxSize {
		back := er.lru.Back()
		if back != nil {
			evict, ok := back.Value.(*CachedEdge)
			if !ok {
				er.lru.Remove(back)
				return nil, false, fmt.Errorf("unexpected cache entry type %T", back.Value)
			}
			if err := er.flushLocked(evict); err != nil {
				return nil, false, err
			}
			delete(er.cache, evict.Key())
			er.lru.Remove(back)
			er.stats.CacheEvictions++
		}
	}

	// Insert at front
	ce.element = er.lru.PushFront(ce)
	er.cache[key] = ce

	return ce, false, nil
}

// Flush

// FlushAll drains the cache and persists all remaining edges.
func (er *EdgeReducer) FlushAll() int {
	er.mu.Lock()
	defer er.mu.Unlock()

	flushed := 0
	for _, ce := range er.cache {
		if err := er.flushLocked(ce); err != nil {
			log.Printf("[reducer] flush error: %v", err)
		}
		flushed++
	}

	// Clear cache
	er.cache = make(map[string]*CachedEdge)
	er.lru = list.New()
	return flushed
}

// FlushOld flushes entries older than the window.
func (er *EdgeReducer) FlushOld() int {
	er.mu.Lock()
	defer er.mu.Unlock()

	cutoff := time.Now().Add(-er.window)
	flushed := 0
	for key, ce := range er.cache {
		if ce.LastSeen.Before(cutoff) {
			if err := er.flushLocked(ce); err != nil {
				log.Printf("[reducer] flush old error: %v", err)
			}
			delete(er.cache, key)
			er.lru.Remove(ce.element)
			flushed++
		}
	}
	return flushed
}

// flushLocked persists a cached edge via the callback.
func (er *EdgeReducer) flushLocked(ce *CachedEdge) error {
	if er.flushFn == nil {
		return nil
	}
	er.stats.FlushedEdges++
	return er.flushFn(ce)
}

// Event mapping

// targetFor computes the target node ID from an event.
func (er *EdgeReducer) targetFor(evt *pb.Event) string {
	switch {
	case evt.ChildPid > 0:
		return fmt.Sprintf("p:%d", evt.ChildPid)
	case evt.Daddr > 0:
		return fmt.Sprintf("n:%s", intToIP(evt.Daddr))
	case evt.Pathname != "":
		if evt.Inode > 0 {
			return fmt.Sprintf("f:%d:%d:%d", evt.Inode, evt.DevMajor, evt.DevMinor)
		}
		return fmt.Sprintf("f:path:%s", evt.Pathname)
	default:
		return "?"
	}
}

// relationFor maps event types to PROV relations.
func (er *EdgeReducer) relationFor(evt *pb.Event) string {
	switch evt.Type {
	case 1: // EV_PROCESS_FORK
		return "wasInformedBy"
	case 2: // EV_PROCESS_EXEC
		return "used"
	case 10, 11, 12: // EV_FILE_OPEN / CREATE / MODIFY
		return "used"
	default:
		return "used"
	}
}

// Helpers

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}

// ToProtoEdge converts a cached edge to a protobuf Edge.
func (ce *CachedEdge) ToProtoEdge() *pb.Edge {
	return &pb.Edge{
		Source:      ce.Source,
		Target:      ce.Target,
		Relation:    ce.Relation,
		TimestampNs: uint64(ce.LastSeen.UnixNano()),
		Count:       uint32(ce.Count),
	}
}

// Stats returns reducer statistics.
func (er *EdgeReducer) Stats() map[string]interface{} {
	er.mu.Lock()
	defer er.mu.Unlock()
	return map[string]interface{}{
		"total_edges":     er.stats.TotalEdges,
		"merged_edges":    er.stats.MergedEdges,
		"flushed_edges":   er.stats.FlushedEdges,
		"cache_evictions": er.stats.CacheEvictions,
		"cache_size":      er.lru.Len(),
		"max_size":        er.maxSize,
		"merge_window":    er.window.String(),
	}
}
