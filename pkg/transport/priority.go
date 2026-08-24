// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
)

// Priority indicates the transmission urgency.
type Priority int

const (
	PriorityLow      Priority = 0 // background, hourly summary
	PriorityNormal   Priority = 1 // normal events
	PriorityHigh     Priority = 2 // tainted or rule-matched
	PriorityCritical Priority = 3 // immediate isolation needed
)

// TransportEvent wraps an event with its transmission priority.
type TransportEvent struct {
	Data      []byte    `json:"-"`    // serialised payload
	Hash      string    `json:"hash"` // content hash
	Priority  Priority  `json:"priority"`
	Tainted   bool      `json:"tainted"`
	RuleMatch bool      `json:"rule_match"`
	Timestamp time.Time `json:"timestamp"`
}

// PriorityPipeline splits events into high/low channels.
// High-priority events (tainted, Sigma-matched) are sent immediately.
// Low-priority events are staged in a Pebble-backed queue and
// aggregated into hourly summary transmissions.
type PriorityPipeline struct {
	mu           sync.Mutex
	highPriority []*TransportEvent // sent immediately
	lowPriority  []*TransportEvent // in-memory fallback for low-priority events
	lowDB        *pebble.DB        // persistent low-priority queue
	lowSeq       uint64            // auto-incrementing sequence
	processed    int64
	highSent     int64
	lowStaged    int64
	maxDrain     int // max events to drain per call (default 10000)
}

// NewPriorityPipeline creates an in-memory priority pipeline.
func NewPriorityPipeline() *PriorityPipeline {
	return &PriorityPipeline{
		maxDrain: 10000,
	}
}

// NewPersistentPriorityPipeline creates a priority pipeline with
// a Pebble-backed low-priority queue for crash recovery.
func NewPersistentPriorityPipeline(path string) (*PriorityPipeline, error) {
	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("open low-priority db: %w", err)
	}

	pp := &PriorityPipeline{
		lowDB:    db,
		maxDrain: 10000,
	}

	// Load the last sequence number from metadata.
	pp.loadSeq()

	log.Printf("[priority] persistent pipeline opened: %s (seq=%d)", path, pp.lowSeq)
	return pp, nil
}

// seqKey is the metadata key for the sequence counter.
func lowSeqKey() []byte { return []byte("lp:seq") }

// loadSeq reads the last sequence number from Pebble.
func (pp *PriorityPipeline) loadSeq() {
	if pp.lowDB == nil {
		return
	}
	data, closer, err := pp.lowDB.Get(lowSeqKey())
	if err != nil {
		return
	}
	defer func() { _ = closer.Close() }()
	if len(data) == 8 {
		pp.lowSeq = binary.BigEndian.Uint64(data)
	}
}

// saveSeq persists the sequence counter.
func (pp *PriorityPipeline) saveSeq() {
	if pp.lowDB == nil {
		return
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, pp.lowSeq)
	if err := pp.lowDB.Set(lowSeqKey(), buf, pebble.Sync); err != nil {
		log.Printf("[priority] save sequence: %v", err)
	}
}

// lowEventKey builds a Pebble key for a low-priority event.
// Format: "lp:<16-hex-seq>" — lexicographically sorted for FIFO.
func lowEventKey(seq uint64) []byte {
	return []byte(fmt.Sprintf("lp:%016x", seq))
}

// Ingest classifies and routes an event.
func (pp *PriorityPipeline) Ingest(evt *TransportEvent) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	switch {
	case evt.Priority >= PriorityHigh || evt.Tainted || evt.RuleMatch:
		pp.highPriority = append(pp.highPriority, evt)
		pp.highSent++
	default:
		if pp.lowDB != nil {
			pp.writeLowToPebbleLocked(evt)
		} else {
			pp.lowPriority = append(pp.lowPriority, evt)
		}
		pp.lowStaged++
	}
}

// writeLowToPebbleLocked persists a low-priority event to Pebble.
// Caller must hold pp.mu.
func (pp *PriorityPipeline) writeLowToPebbleLocked(evt *TransportEvent) {
	pp.lowSeq++
	data, err := json.Marshal(evt)
	if err != nil {
		log.Printf("[priority] marshal low event: %v", err)
		return
	}

	key := lowEventKey(pp.lowSeq)
	batch := pp.lowDB.NewBatch()
	defer func() { _ = batch.Close() }()

	if err := batch.Set(key, data, nil); err != nil {
		log.Printf("[priority] write low event: %v", err)
		return
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, pp.lowSeq)
	if err := batch.Set(lowSeqKey(), buf, nil); err != nil {
		log.Printf("[priority] write sequence: %v", err)
		return
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		log.Printf("[priority] commit low event: %v", err)
	}
}

// DrainHigh returns all high-priority events for immediate sending.
func (pp *PriorityPipeline) DrainHigh() []*TransportEvent {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	out := pp.highPriority
	pp.highPriority = nil
	pp.processed += int64(len(out))
	return out
}

// DrainLowSummary returns a single aggregated summary of low-priority events.
// Events are read from the Pebble queue, aggregated by hash, and then
// deleted. The returned SummaryEvent replaces many individual transmissions
// with one compact report.
func (pp *PriorityPipeline) DrainLowSummary() *SummaryEvent {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	// Collect events from Pebble or in-memory.
	var events []*TransportEvent

	if pp.lowDB != nil {
		events = pp.drainLowFromPebbleLocked()
	} else {
		events = pp.lowPriority
	}

	if len(events) == 0 {
		return nil
	}

	summary := &SummaryEvent{
		Count:     len(events),
		FirstSeen: events[0].Timestamp,
		LastSeen:  events[len(events)-1].Timestamp,
		HashCount: make(map[string]int),
	}

	for _, evt := range events {
		summary.HashCount[evt.Hash]++
	}

	pp.lowPriority = nil
	pp.processed += int64(len(events))

	log.Printf("[priority] LOW summary: %d events, %d unique hashes",
		summary.Count, len(summary.HashCount))
	return summary
}

// drainLowFromPebbleLocked reads all low-priority events from Pebble
// and deletes them. Caller must hold pp.mu.
func (pp *PriorityPipeline) drainLowFromPebbleLocked() []*TransportEvent {
	if pp.lowDB == nil {
		return nil
	}

	iter, err := pp.lowDB.NewIter(&pebble.IterOptions{
		LowerBound: []byte("lp:"),
		UpperBound: []byte("lq:"), // past the last possible key
	})
	if err != nil {
		log.Printf("[priority] iter error: %v", err)
		return nil
	}
	defer func() { _ = iter.Close() }()

	var events []*TransportEvent
	var keys [][]byte

	// Read in batches to bound memory usage.
	for iter.First(); iter.Valid(); iter.Next() {
		if string(iter.Key()) == string(lowSeqKey()) {
			continue
		}
		var evt TransportEvent
		if err := json.Unmarshal(iter.Value(), &evt); err != nil {
			log.Printf("[priority] corrupt low event: %v", err)
			continue
		}
		events = append(events, &evt)
		keys = append(keys, append([]byte{}, iter.Key()...))

		if len(events) >= pp.maxDrain {
			break
		}
	}

	// Delete consumed keys in a batch.
	if len(keys) > 0 {
		batch := pp.lowDB.NewBatch()
		for _, k := range keys {
			_ = batch.Delete(k, nil)
		}
		if err := batch.Commit(pebble.Sync); err != nil {
			log.Printf("[priority] delete low events: %v", err)
		}
		_ = batch.Close()
	}

	return events
}

// LowQueueDepth returns the count of pending low-priority events.
func (pp *PriorityPipeline) LowQueueDepth() int {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	if pp.lowDB != nil {
		iter, err := pp.lowDB.NewIter(&pebble.IterOptions{
			LowerBound: []byte("lp:"),
			UpperBound: []byte("lq:"),
		})
		if err != nil {
			return 0
		}
		defer func() { _ = iter.Close() }()
		count := 0
		for iter.First(); iter.Valid(); iter.Next() {
			if string(iter.Key()) == string(lowSeqKey()) {
				continue
			}
			count++
		}
		return count
	}

	// In-memory fallback.
	return len(pp.lowPriority)
}

// SummaryEvent is the aggregated representation of low-priority events.
// Instead of sending N individual events, one SummaryEvent is transmitted
// per hour with hash frequency counts.
type SummaryEvent struct {
	Count     int            `json:"count"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	HashCount map[string]int `json:"hash_count"` // hash → occurrence count
}

// Stats returns pipeline statistics.
func (pp *PriorityPipeline) Stats() map[string]interface{} {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	return map[string]interface{}{
		"high_sent":  pp.highSent,
		"low_staged": pp.lowStaged,
		"processed":  pp.processed,
		"persistent": pp.lowDB != nil,
	}
}

// Close flushes and closes the Pebble database.
func (pp *PriorityPipeline) Close() error {
	if pp.lowDB != nil {
		return pp.lowDB.Close()
	}
	return nil
}
