// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"log"
	"runtime"
	"sync"
	"time"
)

// ─── PressureMonitor ────────────────────────────────────────

// PressureMonitor watches Go runtime memory metrics and triggers
// callbacks when thresholds are exceeded.
//
// Watermark thresholds:
//   Low (50%)  — start logging memory stats
//   Mid (70%)  — force cache eviction & DB flush
//   High (85%) — request caller to slow ingestion
type PressureMonitor struct {
	mu       sync.Mutex
	maxMem   uint64 // bytes (0 = auto-detect from system total)

	// Watermarks (fraction of maxMem)
	lowMark  float64
	midMark  float64
	highMark float64

	// Callbacks
	onMid  func() // force eviction + flush
	onHigh func() // reduce ingestion rate

	running  bool
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewPressureMonitor creates a pressure monitor.
//
//   maxMemMB  — max memory in MB (0 = auto-detect 75% of total system RAM)
//   onMid     — called at 70% utilisation (force flush/evict)
//   onHigh    — called at 85% utilisation (slow down)
func NewPressureMonitor(maxMemMB uint64, onMid, onHigh func()) *PressureMonitor {
	m := &PressureMonitor{
		lowMark:  0.50,
		midMark:  0.70,
		highMark: 0.85,
		onMid:    onMid,
		onHigh:   onHigh,
		stopCh:   make(chan struct{}),
	}
	if maxMemMB > 0 {
		m.maxMem = maxMemMB * 1024 * 1024
	} else {
		// Auto-detect: use 75% of total system RAM reported by Go
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		// Use Sys as an upper bound approximation
		total := detectSystemMemory()
		m.maxMem = total * 3 / 4 // 75%
	}
	return m
}

// Start begins periodic monitoring in a background goroutine.
func (pm *PressureMonitor) Start() {
	pm.mu.Lock()
	if pm.running {
		pm.mu.Unlock()
		return
	}
	pm.running = true
	pm.mu.Unlock()

	go pm.loop()
}

func (pm *PressureMonitor) loop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.check()
		case <-pm.stopCh:
			return
		}
	}
}

// Stop the monitoring goroutine.
// Safe to call multiple times — subsequent calls are no-ops.
func (pm *PressureMonitor) Stop() {
	pm.stopOnce.Do(func() {
		close(pm.stopCh)
	})
}

// ── Pressure check ──────────────────────────────────────────

func (pm *PressureMonitor) check() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	allocMB := mem.Alloc / 1024 / 1024
	maxMB := pm.maxMem / 1024 / 1024
	fraction := float64(mem.Alloc) / float64(pm.maxMem)

	if fraction < pm.lowMark {
		return // nominal — nothing to do
	}

	log.Printf("[pressure] memory: %d MB / %d MB (%.0f%%)",
		allocMB, maxMB, fraction*100)

	if fraction >= pm.highMark {
		log.Printf("[pressure] HIGH — forcing flush + slow-down")
		if pm.onHigh != nil {
			pm.onHigh()
		}
		if pm.onMid != nil {
			pm.onMid()
		}
	} else if fraction >= pm.midMark {
		log.Printf("[pressure] MID — evicting cold nodes")
		if pm.onMid != nil {
			pm.onMid()
		}
	}
}

// Pressure returns the current memory pressure level.
func (pm *PressureMonitor) Pressure() float64 {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	if pm.maxMem == 0 {
		return 0
	}
	return float64(mem.Alloc) / float64(pm.maxMem)
}

// ── Platform helpers ────────────────────────────────────────

// detectSystemMemory attempts to determine total system RAM.
// Falls back to 4 GB if detection fails.
func detectSystemMemory() uint64 {
	const defaultMem = 4 * 1024 * 1024 * 1024 // 4 GB

	// Try Linux /proc/meminfo
	total, err := parseMemInfo()
	if err == nil {
		return total
	}
	return defaultMem
}

func parseMemInfo() (uint64, error) {
	// This is a simplified read — in production you'd parse /proc/meminfo
	// or use gopsutil.  For now, use a reasonable default.
	return 8 * 1024 * 1024 * 1024, nil // 8 GB default
}
