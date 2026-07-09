// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"fmt"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// MergedEdge accumulates repeated occurrences of the same logical
// edge (same source, target, relation) within a sliding window.
type MergedEdge struct {
	Source    string
	Target    string
	Relation  string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

// toEdge materializes the merged state as a provenance.Edge with
// the accumulated count.
func (m *MergedEdge) toEdge() *provenance.Edge {
	return &provenance.Edge{
		ID:        provenance.EdgeIDCustom(m.Relation, m.Source, m.Target),
		Source:    m.Source,
		Target:    m.Target,
		Relation:  m.Relation,
		Timestamp: m.LastSeen,
		Count:     m.Count,
	}
}

func mergeKey(e *provenance.Edge) string {
	return fmt.Sprintf("%s|%s|%s", e.Source, e.Target, e.Relation)
}

// MergeWindow implements sliding-window deduplication and merging
// of repeated provenance edges.  Within a configurable window (default
// 5 seconds), identical edges (same source+target+relation) are
// merged by incrementing Count and updating LastSeen instead of
// inserting duplicate records.
//
// On each Tick(), all accumulated merged edges are materialized and
// the caller is expected to persist them to RocksDB via the callback.
type MergeWindow struct {
	mu        sync.Mutex
	windowDur time.Duration
	entries   map[string]*MergedEdge
	flushFn   func(*provenance.Edge) error
	tickCount int64
}

// NewMergeWindow creates a merge window.
//
//	windowDur -sliding window duration (0 = 5s)
//	flushFn   -called for each merged edge on Flush
func NewMergeWindow(windowDur time.Duration, flushFn func(*provenance.Edge) error) *MergeWindow {
	if windowDur <= 0 {
		windowDur = 5 * time.Second
	}
	return &MergeWindow{
		windowDur: windowDur,
		entries:   make(map[string]*MergedEdge),
		flushFn:   flushFn,
	}
}

// TryMerge attempts to merge an edge into the current window.
// Returns true if the edge was merged (no write needed), or false
// if the caller should handle it directly.
func (mw *MergeWindow) TryMerge(e *provenance.Edge) bool {
	key := mergeKey(e)

	mw.mu.Lock()
	defer mw.mu.Unlock()

	existing, ok := mw.entries[key]
	if !ok {
		// First occurrence in this window -start tracking
		mw.entries[key] = &MergedEdge{
			Source:    e.Source,
			Target:    e.Target,
			Relation:  e.Relation,
			Count:     1,
			FirstSeen: e.Timestamp,
			LastSeen:  e.Timestamp,
		}
		return false // not merged; caller should write the first occurrence
	}

	// Merge: increment count, update timestamp, skip disk write
	existing.Count++
	if e.Timestamp.After(existing.LastSeen) {
		existing.LastSeen = e.Timestamp
	}
	return true // merged -no write needed
}

// Flush materializes all pending merged edges and sends them through
// the flush callback.  Returns the number of edges flushed.
func (mw *MergeWindow) Flush() (int, error) {
	mw.mu.Lock()
	entries := mw.entries
	mw.entries = make(map[string]*MergedEdge)
	mw.tickCount++
	mw.mu.Unlock()

	if len(entries) == 0 {
		return 0, nil
	}

	flushed := 0
	for _, merged := range entries {
		if err := mw.flushFn(merged.toEdge()); err != nil {
			return flushed, fmt.Errorf("flush merged edge: %w", err)
		}
		flushed++
	}
	return flushed, nil
}

// Pending returns the number of entries pending flush.
func (mw *MergeWindow) Pending() int {
	mw.mu.Lock()
	defer mw.mu.Unlock()
	return len(mw.entries)
}

// Stats returns merge window statistics.
func (mw *MergeWindow) Stats() map[string]interface{} {
	mw.mu.Lock()
	tickCount := mw.tickCount
	mw.mu.Unlock()
	return map[string]interface{}{
		"window_dur": mw.windowDur.String(),
		"pending":    mw.Pending(),
		"ticks":      tickCount,
	}
}
