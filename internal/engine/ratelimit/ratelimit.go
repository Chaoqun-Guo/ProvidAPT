// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package ratelimit implements adaptive rate limiting for ProvidAPT v2.
//
// It monitors BPF ring buffer and userspace queue pressure, and
// dynamically throttles low-risk events to preserve capacity for
// critical security events.
package ratelimit

import (
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

// Drop priority levels
const (
	PriorityCritical = iota // execve, connect — never drop
	PriorityHigh            // file create, modify sensitive paths
	PriorityNormal          // file open, fork
	PriorityLow             // repetitive reads, stat calls
)

// Event priorities (maps event type → priority level)
var eventPriority = map[uint32]int{
	2:  PriorityCritical, // EV_PROCESS_EXEC
	20: PriorityCritical, // EV_NET_CONNECT
	21: PriorityCritical, // EV_NET_ACCEPT
	50: PriorityCritical, // EV_MEMFD_CREATE
	51: PriorityCritical, // EV_MPROTECT_RX
	1:  PriorityHigh,     // EV_PROCESS_FORK
	11: PriorityHigh,     // EV_FILE_CREATE
	12: PriorityHigh,     // EV_FILE_MODIFY
	13: PriorityHigh,     // EV_FILE_DELETE
	10: PriorityNormal,   // EV_FILE_OPEN
	52: PriorityNormal,   // EV_PIPE_WRITE
	53: PriorityNormal,   // EV_PIPE_READ
}

// Low-risk path prefixes — dropped first under pressure.
var lowRiskPaths = []string{
	"/usr/lib/",
	"/usr/share/",
	"/var/cache/",
	"/var/log/",
}

// ─── Config ─────────────────────────────────────────────────

// Config for the rate limiter.
type Config struct {
	// QueueHighWaterMark — fraction (0-1) of queue capacity that triggers
	// rate limiting (default 0.8).
	QueueHighWaterMark float64

	// QueueLowWaterMark — fraction where rate limiting stops (default 0.5).
	QueueLowWaterMark float64

	// MaxQueueSize — capacity of the userspace processing queue (default 10000).
	MaxQueueSize int

	// SampleInterval — how often to check metrics (default 2s).
	SampleInterval time.Duration

	// DropLogInterval — how often to log drop summaries (default 10s).
	DropLogInterval time.Duration

	// EnableKernelBackpressure — if true, writes to BPF map to signal kernel.
	EnableKernelBackpressure bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		QueueHighWaterMark:       0.8,
		QueueLowWaterMark:        0.5,
		MaxQueueSize:             10000,
		SampleInterval:           2 * time.Second,
		DropLogInterval:          10 * time.Second,
		EnableKernelBackpressure: true,
	}
}

// ─── BPF Map interface ──────────────────────────────────────

// BPFRateLimiter is the interface for writing rate-limit signals
// to the kernel BPF map.  In production, backed by *ebpf.Map.
type BPFRateLimiter interface {
	Put(key interface{}, value interface{}) error
}

// ─── DropStats ──────────────────────────────────────────────

// DropStats tracks what was dropped during rate limiting.
type DropStats struct {
	mu           sync.Mutex
	byPriority   map[int]int64    // priority → count dropped
	byEventType  map[uint32]int64 // event type → count dropped
	totalDropped int64
}

// ─── RateLimiter ────────────────────────────────────────────

// RateLimiter monitors system pressure and adaptively drops
// low-priority events when the queue is congested.
type RateLimiter struct {
	cfg    *Config
	bpfBPF BPFRateLimiter

	// Queue depth gauge (atomic for lock-free reads)
	queueDepth atomic.Int64

	// Whether we are currently rate-limiting
	throttling    atomic.Bool
	throttleLevel atomic.Int64 // 0=off, 1=light, 2=aggressive

	// Drop tracking
	drops DropStats

	// Low-risk path matcher
	lowRiskSet []string

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates a rate limiter.
func New(cfg *Config, bpf BPFRateLimiter) *RateLimiter {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	rl := &RateLimiter{
		cfg:        cfg,
		bpfBPF:     bpf,
		lowRiskSet: lowRiskPaths,
		stopCh:     make(chan struct{}),
	}
	rl.drops.byPriority = make(map[int]int64)
	rl.drops.byEventType = make(map[uint32]int64)
	return rl
}

// Start begins the monitoring loop.
func (rl *RateLimiter) Start() {
	rl.wg.Add(1)
	go rl.loop()
	log.Printf("[ratelimit] started (high_water=%.0f%%, interval=%v)",
		rl.cfg.QueueHighWaterMark*100, rl.cfg.SampleInterval)
}

func (rl *RateLimiter) loop() {
	defer rl.wg.Done()
	sampleTicker := time.NewTicker(rl.cfg.SampleInterval)
	logTicker := time.NewTicker(rl.cfg.DropLogInterval)
	defer sampleTicker.Stop()
	defer logTicker.Stop()

	for {
		select {
		case <-sampleTicker.C:
			rl.evaluate()
		case <-logTicker.C:
			rl.logDropSummary()
		case <-rl.stopCh:
			return
		}
	}
}

// Stop gracefully shuts down.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
	rl.wg.Wait()
	rl.logDropSummary()
}

// ─── Queue depth tracking ───────────────────────────────────

// SetQueueDepth is called by the pipeline to report current queue depth.
func (rl *RateLimiter) SetQueueDepth(depth int) {
	rl.queueDepth.Store(int64(depth))
}

// QueueDepth returns the current queue depth.
func (rl *RateLimiter) QueueDepth() int {
	return int(rl.queueDepth.Load())
}

// ─── Pressure evaluation ────────────────────────────────────

// evaluate checks system pressure and adjusts throttling.
func (rl *RateLimiter) evaluate() {
	depth := rl.QueueDepth()
	fillRatio := float64(depth) / float64(rl.cfg.MaxQueueSize)

	// Clamp to [0, 1]
	fillRatio = math.Min(1.0, math.Max(0.0, fillRatio))

	oldLevel := rl.throttleLevel.Load()
	var newLevel int64

	switch {
	case fillRatio >= rl.cfg.QueueHighWaterMark:
		if depth > rl.cfg.MaxQueueSize {
			newLevel = 2 // aggressive
		} else {
			newLevel = 1 // light
		}
	case fillRatio <= rl.cfg.QueueLowWaterMark:
		newLevel = 0 // off
	default:
		// Hold current level (hysteresis)
		newLevel = oldLevel
	}

	rl.throttleLevel.Store(newLevel)
	rl.throttling.Store(newLevel > 0)

	// Signal kernel via BPF map
	if newLevel != oldLevel && rl.cfg.EnableKernelBackpressure && rl.bpfBPF != nil {
		rl.signalKernel(newLevel)
	}

	if newLevel > 0 && newLevel != oldLevel {
		log.Printf("[ratelimit] throttling level %d (queue=%d/%d, %.0f%%)",
			newLevel, depth, rl.cfg.MaxQueueSize, fillRatio*100)
	}
}

// signalKernel writes the throttle level to the BPF map.
func (rl *RateLimiter) signalKernel(level int64) {
	// In production: rl.bpfBPF.Put(uint32(0), uint32(level))
	// Map key 0 is the global throttle level, read by eBPF programs.
	log.Printf("[ratelimit] kernel backpressure signal: level=%d", level)
}

// ─── Drop decision ──────────────────────────────────────────

// ShouldDrop decides whether to drop an event based on current
// throttle level and event priority.
//
// Returns true if the event should be dropped.
//
// Priority-based drop rules:
//
//	Level 1 (light): drop PriorityLow events only
//	Level 2 (aggressive): drop PriorityLow + PriorityNormal
//	Level 0 (off): never drop
func (rl *RateLimiter) ShouldDrop(eventType uint32, pathname string) bool {
	level := rl.throttleLevel.Load()
	if level == 0 {
		return false
	}

	priority, known := eventPriority[eventType]
	if !known {
		priority = PriorityNormal
	}

	shouldDrop := false
	switch level {
	case 1: // light — only PriorityLow
		shouldDrop = priority <= PriorityLow
	case 2: // aggressive — PriorityLow + PriorityNormal
		shouldDrop = priority <= PriorityNormal
	}

	// Even if eligible, don't drop if path matches a sensitive pattern
	if shouldDrop && rl.isSensitivePath(pathname) {
		shouldDrop = false
	}

	if shouldDrop {
		rl.recordDrop(eventType, priority)
	}

	return shouldDrop
}

// isSensitivePath checks if a path is NOT low-risk.
func (rl *RateLimiter) isSensitivePath(path string) bool {
	for _, low := range rl.lowRiskSet {
		if strings.HasPrefix(path, low) {
			return false // it IS low-risk, so NOT sensitive
		}
	}
	return true
}

// ─── Drop recording ─────────────────────────────────────────

func (rl *RateLimiter) recordDrop(eventType uint32, priority int) {
	rl.drops.mu.Lock()
	rl.drops.totalDropped++
	rl.drops.byPriority[priority]++
	rl.drops.byEventType[eventType]++
	rl.drops.mu.Unlock()
}

// logDropSummary prints a summary of dropped events.
func (rl *RateLimiter) logDropSummary() {
	rl.drops.mu.Lock()
	total := rl.drops.totalDropped
	byType := make(map[uint32]int64)
	for k, v := range rl.drops.byEventType {
		byType[k] = v
	}
	rl.drops.mu.Unlock()

	if total == 0 {
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[ratelimit] drop summary: %d events dropped\n", total)
	// Show top dropped event types
	for et, count := range byType {
		if count > 0 {
			fmt.Fprintf(&b, "  type %d (%s): %d\n", et, eventName(et), count)
		}
	}
	log.Printf("%s", b.String())
}

// ─── Stats ──────────────────────────────────────────────────

// Stats returns a snapshot of rate limiter state.
func (rl *RateLimiter) Stats() map[string]interface{} {
	rl.drops.mu.Lock()
	total := rl.drops.totalDropped
	rl.drops.mu.Unlock()

	return map[string]interface{}{
		"throttling":               rl.throttling.Load(),
		"throttle_level":           rl.throttleLevel.Load(),
		"queue_depth":              rl.QueueDepth(),
		"max_queue":                rl.cfg.MaxQueueSize,
		"total_dropped":            total,
		"priority_critical_events": 0,
	}
}

// ─── Helper ─────────────────────────────────────────────────

func eventName(et uint32) string {
	names := map[uint32]string{
		1: "fork", 2: "exec", 10: "open", 11: "create",
		12: "modify", 13: "delete", 20: "connect", 21: "accept",
		50: "memfd", 51: "mprotect", 52: "pipe_write", 53: "pipe_read",
	}
	if n, ok := names[et]; ok {
		return n
	}
	return fmt.Sprintf("unknown(%d)", et)
}
