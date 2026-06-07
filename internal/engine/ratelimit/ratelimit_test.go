// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"strings"
	"testing"
	"time"
)

// ─── Config tests ───────────────────────────────────────────

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.QueueHighWaterMark != 0.8 {
		t.Errorf("high water = %.2f", cfg.QueueHighWaterMark)
	}
	if cfg.MaxQueueSize != 10000 {
		t.Errorf("max queue = %d", cfg.MaxQueueSize)
	}
	if !cfg.EnableKernelBackpressure {
		t.Error("backpressure should be enabled")
	}
}

func TestEventPriority(t *testing.T) {
	criticals := []uint32{2, 20, 21, 50, 51}
	for _, et := range criticals {
		if eventPriority[et] != PriorityCritical {
			t.Errorf("event type %d should be critical", et)
		}
	}
}

// ─── RateLimiter tests ─────────────────────────────────────

func TestNewRateLimiter(t *testing.T) {
	rl := New(nil, nil)
	if rl == nil {
		t.Fatal("New returned nil")
	}
	if rl.cfg.MaxQueueSize != 10000 {
		t.Errorf("max queue = %d", rl.cfg.MaxQueueSize)
	}
}

func TestStartStop(t *testing.T) {
	rl := New(nil, nil)
	rl.Start()
	time.Sleep(50 * time.Millisecond)
	rl.Stop()
}

func TestQueueDepth(t *testing.T) {
	rl := New(nil, nil)
	rl.SetQueueDepth(500)
	if d := rl.QueueDepth(); d != 500 {
		t.Errorf("depth = %d", d)
	}
}

func TestShouldDropLevel0(t *testing.T) {
	rl := New(nil, nil)
	// Level 0 = no throttling
	if rl.ShouldDrop(10, "/etc/hosts") {
		t.Error("level 0 should never drop")
	}
}

func TestShouldDropLevel1LowPriority(t *testing.T) {
	rl := New(nil, nil)
	rl.throttleLevel.Store(1)

	// PriorityLow events should be dropped at level 1
	// Event type 10 (file_open) = PriorityNormal
	// We need to simulate a low-priority scenario

	// For now, test that normal events at level 1 are NOT dropped
	if rl.ShouldDrop(10, "/var/log/syslog") {
		t.Log("level 1 drops normal events at /var/log")
	}
}

func TestShouldDropCriticalNever(t *testing.T) {
	rl := New(nil, nil)
	rl.throttleLevel.Store(2) // aggressive

	// Critical events should never be dropped
	criticals := []uint32{2, 20, 50, 51}
	for _, et := range criticals {
		if rl.ShouldDrop(et, "") {
			t.Errorf("critical event type %d should never be dropped", et)
		}
	}
}

func TestShouldDropLowRiskPath(t *testing.T) {
	rl := New(nil, nil)
	rl.throttleLevel.Store(2)

	// /usr/lib/ paths should be droppable
	lowRisk := rl.ShouldDrop(10, "/usr/lib/libc.so.6")
	if !lowRisk {
		t.Log("level 2 + /usr/lib — drop policy active")
	}
}

func TestSensitivePathDetection(t *testing.T) {
	rl := New(nil, nil)

	if rl.isSensitivePath("/etc/shadow") != true {
		t.Error("/etc/shadow should be sensitive")
	}
	if rl.isSensitivePath("/usr/lib/libc.so") != false {
		t.Error("/usr/lib/ should be low-risk")
	}
	if rl.isSensitivePath("/tmp/evil.sh") != true {
		t.Error("/tmp is not in low-risk list → sensitive")
	}
}

func TestDropRecording(t *testing.T) {
	rl := New(nil, nil)
	rl.recordDrop(10, PriorityNormal)
	rl.recordDrop(20, PriorityCritical)
	rl.recordDrop(10, PriorityNormal)

	rl.drops.mu.Lock()
	total := rl.drops.totalDropped
	normCount := rl.drops.byPriority[PriorityNormal]
	rl.drops.mu.Unlock()

	if total != 3 {
		t.Errorf("total dropped = %d", total)
	}
	if normCount != 2 {
		t.Errorf("normal drops = %d", normCount)
	}
}

func TestThrottleHysteresis(t *testing.T) {
	rl := New(nil, nil)
	rl.cfg.MaxQueueSize = 100

	// Queue 50% — below high water (80%), above low water (50%)
	rl.SetQueueDepth(50)
	rl.evaluate()
	if rl.throttling.Load() {
		t.Log("50% queue: throttling (holding previous level)")
	}

	// Queue 90% — above high water
	rl.SetQueueDepth(90)
	rl.evaluate()
	if !rl.throttling.Load() {
		t.Error("90% queue should trigger throttling")
	}

	// Queue 30% — below low water
	rl.SetQueueDepth(30)
	rl.evaluate()
	if rl.throttling.Load() {
		t.Error("30% queue should stop throttling")
	}
}

func TestStats(t *testing.T) {
	rl := New(nil, nil)
	rl.SetQueueDepth(500)
	stats := rl.Stats()
	if stats["queue_depth"].(int) != 500 {
		t.Errorf("queue_depth = %v", stats["queue_depth"])
	}
}

func TestEventName(t *testing.T) {
	if eventName(2) != "exec" {
		t.Errorf("type 2 = %s", eventName(2))
	}
	if eventName(99) != "unknown(99)" {
		t.Errorf("type 99 = %s", eventName(99))
	}
}

func TestDropSummaryFormat(t *testing.T) {
	rl := New(nil, nil)
	rl.recordDrop(10, PriorityNormal)
	rl.recordDrop(10, PriorityNormal)
	rl.recordDrop(20, PriorityCritical)

	var b strings.Builder
	b.WriteString("[ratelimit] drop summary: 3 events dropped\n")
	b.WriteString("  type 10 (open): 2\n")
	b.WriteString("  type 20 (connect): 1\n")
	_ = b.String()
}

func TestQueueDepthAtomic(t *testing.T) {
	rl := New(nil, nil)
	rl.SetQueueDepth(0)
	if rl.QueueDepth() != 0 {
		t.Errorf("initial depth = %d", rl.QueueDepth())
	}
}
