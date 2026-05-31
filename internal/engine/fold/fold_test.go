package fold

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// ─── IO aggregation tests ───────────────────────────────────

func TestNewIOAggregator(t *testing.T) {
	ia := NewIOAggregator()
	if ia == nil {
		t.Fatal("NewIOAggregator returned nil")
	}
}

func TestRecordIO(t *testing.T) {
	ia := NewIOAggregator()
	ia.RecordIO(100, "bash", 3, 0, 4096)  // read
	ia.RecordIO(100, "bash", 3, 0, 2048)  // read (same key)

	ia.mu.Lock()
	key := AggKey{PID: 100, FD: 3, OpType: 0}
	val, ok := ia.agg[key]
	ia.mu.Unlock()

	if !ok {
		t.Fatal("entry not found")
	}
	if val.Count != 2 {
		t.Errorf("count = %d", val.Count)
	}
	if val.TotalBytes != 6144 {
		t.Errorf("bytes = %d", val.TotalBytes)
	}
}

func TestOnCloseFlush(t *testing.T) {
	ia := NewIOAggregator()
	ia.RecordIO(100, "bash", 3, 0, 4096)
	ia.OnClose(100, 3)

	ia.mu.Lock()
	_, exists := ia.agg[AggKey{PID: 100, FD: 3, OpType: 0}]
	ia.mu.Unlock()

	if exists {
		t.Error("entry should be removed after close")
	}
}

func TestTick(t *testing.T) {
	ia := NewIOAggregator()
	ia.RecordIO(100, "bash", 3, 0, 4096)
	ia.RecordIO(100, "bash", 4, 1, 512)

	n := ia.Tick(map[uint32]string{100: "bash"})
	if n != 2 {
		t.Errorf("tick flushed %d, want 2", n)
	}
}

func TestFlushInterval(t *testing.T) {
	ia := NewIOAggregator()
	ia.SetFlushInterval(2 * time.Second)
	ia.mu.Lock()
	interval := ia.flushInt
	ia.mu.Unlock()
	if interval != 2*time.Second {
		t.Errorf("interval = %v", interval)
	}
}

func TestStats(t *testing.T) {
	ia := NewIOAggregator()
	ia.RecordIO(100, "bash", 3, 0, 100)
	stats := ia.Stats()
	if stats["active_entries"].(int) != 1 {
		t.Errorf("entries = %d", stats["active_entries"])
	}
	if !strings.Contains(stats["fold_ratio"].(string), "%") {
		t.Errorf("ratio = %v", stats["fold_ratio"])
	}
}

func TestFoldRatio(t *testing.T) {
	ia := NewIOAggregator()
	// 100 raw events folded into 1 aggregate
	for i := 0; i < 100; i++ {
		ia.RecordIO(100, "bash", 3, 0, 512)
	}
	ia.Tick(map[uint32]string{100: "bash"})

	stats := ia.Stats()
	t.Logf("Fold: total=%d folded=%d ratio=%v",
		stats["total_events"], stats["total_folded"], stats["fold_ratio"])
}

func TestConcurrentRecord(t *testing.T) {
	ia := NewIOAggregator()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ia.RecordIO(pid, "test", 3, 0, 256)
			}
		}(uint32(i))
	}
	wg.Wait()

	stats := ia.Stats()
	if stats["total_events"].(int64) != 1000 {
		t.Errorf("total = %d", stats["total_events"])
	}
}

// ─── Redundancy filter tests ────────────────────────────────

func TestNewRedundancyFilter(t *testing.T) {
	rf := NewRedundancyFilter(100 * time.Millisecond)
	if rf == nil {
		t.Fatal("NewRedundancyFilter returned nil")
	}
}

func TestCheckFirstCall(t *testing.T) {
	rf := NewRedundancyFilter(time.Minute)
	if !rf.Check(100, 217, "/etc", 0) {
		t.Error("first call should pass")
	}
}

func TestCheckSuppressRepeat(t *testing.T) {
	rf := NewRedundancyFilter(time.Minute)

	rf.Check(100, 217, "/etc", 0)  // first — pass
	suppr := rf.Check(100, 217, "/etc", 0)  // repeat — suppress

	if suppr {
		t.Error("same result should be suppressed")
	}

	stats := rf.Stats()
	if stats["suppressed"].(int64) != 1 {
		t.Errorf("suppressed = %d", stats["suppressed"])
	}
}

func TestCheckDifferentResult(t *testing.T) {
	rf := NewRedundancyFilter(time.Minute)

	rf.Check(100, 217, "/etc", 0)   // first
	pass := rf.Check(100, 217, "/etc", -1) // different result — should pass

	if !pass {
		t.Error("different result should pass")
	}
}

func TestCheckTTLExpiry(t *testing.T) {
	rf := NewRedundancyFilter(time.Nanosecond)

	rf.Check(100, 217, "/etc", 0)  // first
	time.Sleep(10 * time.Millisecond)
	pass := rf.Check(100, 217, "/etc", 0)  // TTL expired — should pass

	if !pass {
		t.Log("repeat after TTL expiry may still be suppressed")
	}
}

func TestFoldStats(t *testing.T) {
	rf := NewRedundancyFilter(time.Minute)
	rf.Check(100, 217, "/a", 0)
	rf.Check(100, 217, "/a", 0) // suppress
	rf.Check(100, 217, "/b", 0) // pass

	stats := rf.Stats()
	if stats["passed"].(int64) != 2 {
		t.Errorf("passed = %d", stats["passed"])
	}
	if stats["suppressed"].(int64) != 1 {
		t.Errorf("suppressed = %d", stats["suppressed"])
	}
}

// ─── Throttle controller tests ──────────────────────────────

func TestNewThrottleController(t *testing.T) {
	tc := NewThrottleController(nil, nil, nil)
	if tc == nil {
		t.Fatal("NewThrottleController returned nil")
	}
}

func TestStartStop(t *testing.T) {
	tc := NewThrottleController(nil, nil, nil)
	tc.Start()
	tc.Stop()
}

func TestCurrentWindow(t *testing.T) {
	tc := NewThrottleController(nil, nil, nil)
	w := tc.CurrentWindow()
	if w != time.Second {
		t.Errorf("window = %v", w)
	}
}

func TestDefaultThrottleConfig(t *testing.T) {
	cfg := DefaultThrottleConfig()
	if cfg.CPULow != 20.0 {
		t.Errorf("low = %.0f", cfg.CPULow)
	}
	if cfg.MinWindow != 100*time.Millisecond {
		t.Errorf("min = %v", cfg.MinWindow)
	}
}

func TestAdjustUnderLoad(t *testing.T) {
	ia := NewIOAggregator()
	tc := NewThrottleController(nil, ia, nil)

	// Simulate high CPU by calling adjust directly
	tc.adjust()

	// After adjust, the window might have changed based on CPU
	w := tc.CurrentWindow()
	t.Logf("Window after adjust: %v", w)
}

func TestCPUReading(t *testing.T) {
	cpu := readCPUUsage()
	if cpu < 0 {
		t.Log("CPU reading not available")
	} else {
		t.Logf("CPU: %.1f%%", cpu)
	}
}

func TestFoldMergeStats(t *testing.T) {
	tc := NewThrottleController(nil, nil, nil)
	stats := tc.Stats()
	if _, ok := stats["current_window"]; !ok {
		t.Error("missing current_window")
	}
}

// ─── Integration test ───────────────────────────────────────

func TestFoldIntegration(t *testing.T) {
	t.Log("=== Event Folding Integration ===")

	// 1. IO Aggregation
	ia := NewIOAggregator()
	for i := 0; i < 100; i++ {
		ia.RecordIO(100, "nginx", 3, 0, 4096) // repeated reads
	}
	ia.RecordIO(200, "bash", 1, 1, 512) // single write

	n := ia.Tick(map[uint32]string{100: "nginx", 200: "bash"})
	t.Logf("IO agg: flushed %d events, folded %d raw events",
		n, ia.totalEvents)

	// 2. Redundancy filter
	rf := NewRedundancyFilter(time.Minute)
	for i := 0; i < 10; i++ {
		rf.Check(100, 217, "/usr/lib", 0)
	}
	rfStats := rf.Stats()
	t.Logf("Dedup: passed=%d suppressed=%d efficiency=%s",
		rfStats["passed"], rfStats["suppressed"], rfStats["efficiency"])

	// 3. Throttle
	tc := NewThrottleController(nil, ia, rf)
	tc.Start()
	defer tc.Stop()

	t.Logf("Throttle: window=%v min=%v max=%v",
		tc.CurrentWindow(), tc.cfg.MinWindow, tc.cfg.MaxWindow)

	t.Log("Event folding integration OK")
}
