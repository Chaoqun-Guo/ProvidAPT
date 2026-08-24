// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"fmt"
	"log"
	"sync"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

// ═══════════════════════════════════════════════════════════════
// Filter decision
// ═══════════════════════════════════════════════════════════════

// Decision is returned by the engine for each event.
type Decision int

const (
	DecisionProcess  Decision = iota // persist + analyze (default)
	DecisionLowLevel                 // memory-only counter, no persist
	DecisionDrop                     // completely discard
)

func (d Decision) String() string {
	switch d {
	case DecisionProcess:
		return "PROCESS"
	case DecisionLowLevel:
		return "LOW_LEVEL"
	case DecisionDrop:
		return "DROP"
	default:
		return "UNKNOWN"
	}
}

// ═══════════════════════════════════════════════════════════════
// Engine
// ═══════════════════════════════════════════════════════════════

// Engine combines baseline whitelist + path reputation to decide
// how each event should be handled.
type Engine struct {
	baseline *Baseline
	repute   *Reputation

	mu       sync.Mutex
	counters map[string]int64 // hash → count (low-level events)

	// statistics
	totalEvents    int64
	lowLevelEvents int64
	droppedEvents  int64
	filteredBytes  int64 // estimated saved storage
}

// NewEngine creates a filtering engine.
func NewEngine(baseline *Baseline, repute *Reputation) *Engine {
	return &Engine{
		baseline: baseline,
		repute:   repute,
		counters: make(map[string]int64),
	}
}

// ── Filter logic ────────────────────────────────────────────

// Decide evaluates an event and returns how it should be processed.
func (e *Engine) Decide(evt *collector.Event) Decision {
	e.mu.Lock()
	e.totalEvents++
	e.mu.Unlock()

	// 1. During training, record everything
	if e.baseline.IsTraining() {
		e.baseline.Record(Hash(evt))
		return DecisionProcess
	}

	// 2. Check for sensitive operations — always process
	if e.isSensitive(evt) {
		return DecisionProcess
	}

	// 3. Compute behavioral hash
	hash := Hash(evt)

	// 4. Check baseline whitelist
	if !e.baseline.IsKnown(hash) {
		return DecisionProcess // unknown pattern → process normally
	}

	// 5. Known benign pattern — apply reputation
	commRep := e.repute.ScoreComm(evt.Comm)
	pathRep := e.repute.ScorePath(evt.Pathname)
	combined := (commRep + pathRep) / 2

	if ShouldAggressivelyMerge(combined) {
		e.mu.Lock()
		e.counters[hash]++
		e.lowLevelEvents++
		e.filteredBytes += 332 // estimated raw event size
		e.mu.Unlock()
		return DecisionLowLevel
	}

	// Normal reputation — still benign but not aggressively merged
	e.mu.Lock()
	e.lowLevelEvents++
	e.mu.Unlock()
	return DecisionLowLevel
}

// ── Sensitivity check ───────────────────────────────────────

func (e *Engine) isSensitive(evt *collector.Event) bool {
	// Always capture setuid / credential changes
	if evt.Flags&syscall.EventFlagExecSetuid != 0 {
		return true
	}
	// Always capture network connections
	if evt.Type == syscall.EventNetConnect || evt.Type == syscall.EventNetAccept {
		return true
	}
	// Always capture writes to sensitive paths
	if isSensitivePath(evt.Pathname) && evt.FFlags != 0 {
		return true
	}
	return false
}

// isSensitivePath checks against known sensitive paths.
func isSensitivePath(path string) bool {
	sensitive := []string{
		"/etc/shadow", "/etc/passwd", "/etc/sudoers",
		"/etc/ssh/", "/root/", "/.ssh/",
		"/var/log/auth.log",
	}
	for _, p := range sensitive {
		if len(path) >= len(p) && path[:len(p)] == p {
			return true
		}
	}
	return false
}

// ── Query low-level counters ────────────────────────────────

// LowLevelCounts returns the hash → count map for filtered events.
func (e *Engine) LowLevelCounts() map[string]int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]int64, len(e.counters))
	for k, v := range e.counters {
		out[k] = v
	}
	return out
}

// ResetCounters clears low-level counters (called after periodic flush).
func (e *Engine) ResetCounters() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.counters = make(map[string]int64)
}

// ── Periodic flush to RocksDB (summary record) ──────────────

// FlushSummary writes a summary of filtered events to the store.
// This saves a single record per hash instead of thousands of
// individual events.
func (e *Engine) FlushSummary(store PersistReadWriter) error {
	counts := e.LowLevelCounts()
	if len(counts) == 0 {
		return nil
	}

	for hash, count := range counts {
		key := "filter:lowlevel:" + hash
		if store != nil {
			if err := store.Put(key, []byte(fmt.Sprintf(`{"hash":"%s","count":%d}`, hash, count))); err != nil {
				log.Printf("[filter] flush summary: %v", err)
			}
		}
	}

	e.ResetCounters()
	log.Printf("[filter] flushed %d low-level summaries", len(counts))
	return nil
}

// ── Stats ───────────────────────────────────────────────────

func (e *Engine) Stats() map[string]interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]interface{}{
		"total_events":    e.totalEvents,
		"low_level":       e.lowLevelEvents,
		"dropped":         e.droppedEvents,
		"filtered_bytes":  e.filteredBytes,
		"active_counters": len(e.counters),
		"baseline":        e.baseline.Stats(),
	}
}
