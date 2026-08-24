// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package stream implements a streaming graph construction engine
// for ProvidAPT, enabling millisecond-level attack response.
//
// It replaces batch-processing with a stream-processing architecture
// inspired by Apache Flink, featuring:
//
//  1. Streaming graph construction — events are processed in micro-
//     batches (5s windows) and immediately matched against APT patterns.
//
//  2. NFA-based pattern matching — real-time detection of TTP
//     sequences using nondeterministic finite automata.
//
//  3. Rolling memory snapshots — fast retrieval of recent (1 hour)
//     associations without disk I/O.
package stream

import (
	"log"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Stream engine
// ═══════════════════════════════════════════════════════════════

// EngineConfig for the streaming engine.
type EngineConfig struct {
	// MicroBatchWindow is the size of each micro-batch (default 5s).
	MicroBatchWindow time.Duration

	// SnapshotWindow is how far back the rolling memory snapshot keeps (default 1h).
	SnapshotWindow time.Duration

	// EventChBuffer is the channel buffer size (default 10000).
	EventChBuffer int

	// EnableNFA enables NFA-based pattern matching.
	EnableNFA bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *EngineConfig {
	return &EngineConfig{
		MicroBatchWindow: 5 * time.Second,
		SnapshotWindow:   1 * time.Hour,
		EventChBuffer:    10000,
		EnableNFA:        true,
	}
}

// Engine is the streaming graph construction engine.
type Engine struct {
	cfg      *EngineConfig
	graph    *provenance.Graph
	nfa      *NFAEngine
	snapshot *RollingSnapshot

	eventCh chan *collector.Event
	alertCh chan *PatternMatch

	mu     sync.Mutex
	events []*collector.Event // current micro-batch
	wg     sync.WaitGroup
	stopCh chan struct{}
}

// New creates a streaming engine.
func New(graph *provenance.Graph, cfg *EngineConfig) *Engine {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	e := &Engine{
		cfg:      cfg,
		graph:    graph,
		eventCh:  make(chan *collector.Event, cfg.EventChBuffer),
		alertCh:  make(chan *PatternMatch, 128),
		stopCh:   make(chan struct{}),
		snapshot: NewRollingSnapshot(cfg.SnapshotWindow),
	}

	if cfg.EnableNFA {
		e.nfa = NewNFAEngine()
	}

	return e
}

// Start begins the stream processing goroutines.
func (e *Engine) Start() {
	e.wg.Add(2)
	go e.microBatchLoop()
	go e.snapshotSyncLoop()
	log.Printf("[stream] engine started (batch=%s, snap=%s, nfa=%v)",
		e.cfg.MicroBatchWindow, e.cfg.SnapshotWindow, e.cfg.EnableNFA)
}

// EventCh returns the input channel for events.
func (e *Engine) EventCh() chan<- *collector.Event {
	return e.eventCh
}

// AlertCh returns the output channel for pattern matches.
func (e *Engine) AlertCh() <-chan *PatternMatch {
	return e.alertCh
}

// Stop gracefully shuts down the engine.
func (e *Engine) Stop() {
	close(e.stopCh)
	e.wg.Wait()
	close(e.alertCh)
}

// microBatchLoop processes events in micro-batches.
func (e *Engine) microBatchLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(e.cfg.MicroBatchWindow)
	defer ticker.Stop()

	for {
		select {
		case evt := <-e.eventCh:
			e.mu.Lock()
			e.events = append(e.events, evt)
			e.mu.Unlock()

		case <-ticker.C:
			e.flushMicroBatch()

		case <-e.stopCh:
			e.flushMicroBatch()
			return
		}
	}
}

// flushMicroBatch processes all accumulated events.
func (e *Engine) flushMicroBatch() {
	e.mu.Lock()
	batch := e.events
	e.events = nil
	e.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	// Process each event through the graph and NFA
	for _, evt := range batch {
		e.processEvent(evt)
	}
}

// processEvent handles a single event.
func (e *Engine) processEvent(evt *collector.Event) {
	// 1. Add to provenance graph
	e.graph.AddEvent(evt)

	// 2. Update rolling snapshot
	e.snapshot.Add(evt)

	// 3. Run NFA pattern matching
	if e.nfa != nil {
		matches := e.nfa.Ingest(evt)
		for _, match := range matches {
			select {
			case e.alertCh <- match:
			default:
				log.Printf("[stream] alert channel full, dropping match: %s", match.PatternID)
			}
		}
	}
}

// snapshotSyncLoop periodically syncs the rolling snapshot.
func (e *Engine) snapshotSyncLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.snapshot.Evict()
		case <-e.stopCh:
			return
		}
	}
}

// Snapshot returns the current rolling memory snapshot.
func (e *Engine) Snapshot() *RollingSnapshot {
	return e.snapshot
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	return map[string]interface{}{
		"micro_batch_window": e.cfg.MicroBatchWindow.String(),
		"snapshot_window":    e.cfg.SnapshotWindow.String(),
		"nfa_enabled":        e.cfg.EnableNFA,
		"nfa_active_states":  e.nfa.ActiveStates(),
		"snapshot_events":    e.snapshot.Size(),
	}
}
