package profile

import (
	"strings"
	"testing"
	"time"
	"sync/atomic"
)

// ─── BPF stats tests ────────────────────────────────────────

func TestCollectBPFStats(t *testing.T) {
	stats, err := CollectBPFStats()
	if err != nil {
		t.Skipf("bpftool not available: %v", err)
	}
	if stats == nil {
		t.Fatal("nil stats")
	}
	t.Logf("BPF programs: %d", len(stats.Programs))
	t.Logf("Total runs:   %d", stats.TotalRuns)
	for _, p := range stats.Programs {
		t.Logf("  [%d] %s — %d runs, %.0f ns avg", p.ID, p.Name, p.RunCount, p.AvgRunNS)
	}
}

func TestExtractAfter(t *testing.T) {
	s := "run_time_ns 12345 run_cnt 678"
	if v := extractAfter(s, "run_time_ns"); v != 12345 {
		t.Errorf("run_time_ns = %d", v)
	}
	if v := extractAfter(s, "run_cnt"); v != 678 {
		t.Errorf("run_cnt = %d", v)
	}
	if v := extractAfter(s, "nonexistent"); v != 0 {
		t.Errorf("nonexistent = %d", v)
	}
}

// ─── Storage stats tests ────────────────────────────────────

func TestNewStorageStats(t *testing.T) {
	ss := NewStorageStats()
	if ss == nil {
		t.Fatal("NewStorageStats returned nil")
	}
}

func TestRecordWrite(t *testing.T) {
	ss := NewStorageStats()
	ss.RecordWrite(5*time.Millisecond, 10, 20)
	ss.RecordWrite(3*time.Millisecond, 5, 15)

	if ss.NodesPerSecond() <= 0 {
		t.Log("NPS = 0 (expected if no time elapsed)")
	}
}

func TestAvgWriteLatency(t *testing.T) {
	ss := NewStorageStats()
	ss.RecordWrite(10*time.Millisecond, 1, 0)
	ss.RecordWrite(20*time.Millisecond, 1, 0)

	avg := ss.AvgWriteLatency()
	if avg < 10*time.Millisecond || avg > 20*time.Millisecond {
		t.Errorf("avg latency = %v", avg)
	}
}

func TestWindowLatencyP99(t *testing.T) {
	ss := NewStorageStats()
	for i := 0; i < 100; i++ {
		ss.RecordWrite(time.Duration(i)*time.Millisecond, 1, 0)
	}
	p99 := ss.WindowLatencyP99()
	if p99 <= 0 {
		t.Error("P99 should be > 0")
	}
	t.Logf("P99 latency: %v", p99)
}

func TestResetWindow(t *testing.T) {
	ss := NewStorageStats()
	ss.RecordWrite(10*time.Millisecond, 1, 0)
	ss.ResetWindow()
	if wc := atomic.LoadInt64(&ss.windowCount); wc != 0 {
		t.Errorf("window count = %d after reset", wc)
	}
}

// ─── System stats tests ─────────────────────────────────────

func TestCollectSystemStats(t *testing.T) {
	stats := CollectSystemStats()
	if stats == nil {
		t.Fatal("nil stats")
	}
	if stats.MemoryRSSMB <= 0 {
		t.Logf("Memory RSS: %.0f MB (may be 0 on some platforms)", stats.MemoryRSSMB)
	}
	if stats.Goroutines <= 0 {
		t.Error("goroutines should be > 0")
	}
	if stats.GoVersion == "" {
		t.Error("go version should not be empty")
	}
	t.Logf("System: CPU=%.1f%% Mem=%.0fMB Go=%s Goroutines=%d FDs=%d",
		stats.CPUPercent, stats.MemoryRSSMB, stats.GoVersion,
		stats.Goroutines, stats.FDCount)
}

func TestSystemStatsFields(t *testing.T) {
	stats := CollectSystemStats()
	if stats.FDCount == 0 {
		t.Log("FD count = 0 (may not be available on all platforms)")
	}
}

// ─── Profile report tests ───────────────────────────────────

func TestCollectProfile(t *testing.T) {
	ss := NewStorageStats()
	ss.RecordWrite(5*time.Millisecond, 100, 50)
	ss.RecordWrite(3*time.Millisecond, 200, 75)

	report := CollectProfile(ss)
	if report == nil {
		t.Fatal("nil report")
	}
	if report.Timestamp == "" {
		t.Error("missing timestamp")
	}
	if report.System == nil {
		t.Error("missing system stats")
	}
	if report.Storage == nil {
		t.Error("missing storage stats")
	}
	t.Logf("Profile: %s", report.String())
}

func TestProfileWithNilStorage(t *testing.T) {
	report := CollectProfile(nil)
	if report.Storage == nil {
		t.Error("storage should be non-nil even with nil input")
	}
}

func TestProfileString(t *testing.T) {
	ss := NewStorageStats()
	ss.RecordWrite(5*time.Millisecond, 100, 50)
	report := CollectProfile(ss)
	s := report.String()
	if !strings.Contains(s, "ProvidAPT Performance") {
		t.Errorf("missing header: %s", s)
	}
	if !strings.Contains(s, "eBPF") {
		t.Log("no BPF section (bpftool may not be available)")
	}
	t.Logf("Full report:\n%s", s)
}

func TestProfileLog(t *testing.T) {
	ss := NewStorageStats()
	report := CollectProfile(ss)
	// Should not panic
	report.Log()
}

func TestProfileReportDuration(t *testing.T) {
	report := CollectProfile(nil)
	if report.Duration == "" {
		t.Error("duration should be set")
	}
}

func TestConcurrentWrites(t *testing.T) {
	ss := NewStorageStats()
	done := make(chan bool)

	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				ss.RecordWrite(time.Millisecond, 1, 0)
			}
			done <- true
		}()
	}

	for i := 0; i < 5; i++ {
		<-done
	}

	total := atomic.LoadInt64(&ss.nodesWritten)
	if total != 500 {
		t.Errorf("total nodes = %d, want 500", total)
	}
}
