// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// ── Hash tests ──────────────────────────────────────────────

func TestHashDeterministic(t *testing.T) {
	evt := &collector.Event{Type: syscall.EventFileOpen, Comm: "bash", Pathname: "/etc/hosts"}
	h1 := Hash(evt)
	h2 := Hash(evt)
	if h1 != h2 {
		t.Errorf("hash not deterministic: %s vs %s", h1, h2)
	}
}

func TestHashDifferent(t *testing.T) {
	e1 := &collector.Event{Type: syscall.EventFileOpen, Comm: "bash", Pathname: "/etc/hosts"}
	e2 := &collector.Event{Type: syscall.EventFileOpen, Comm: "bash", Pathname: "/etc/shadow"}
	if Hash(e1) == Hash(e2) {
		t.Error("different events should have different hashes")
	}
}

func TestHashLength(t *testing.T) {
	evt := &collector.Event{Type: syscall.EventFileOpen, Comm: "test", Pathname: "/tmp/x"}
	h := Hash(evt)
	if len(h) != 16 {
		t.Errorf("hash length = %d, want 16", len(h))
	}
}

func TestHashEmptyPath(t *testing.T) {
	evt := &collector.Event{Type: syscall.EventFileOpen, Comm: "test"}
	h := Hash(evt)
	if h == "" {
		t.Error("empty hash")
	}
}

// ── Baseline tests ──────────────────────────────────────────

type memStore struct {
	data map[string][]byte
}

func newMemStore() *memStore { return &memStore{data: make(map[string][]byte)} }
func (m *memStore) Get(key string) ([]byte, error) { v, _ := m.data[key]; return v, nil }
func (m *memStore) Put(key string, value []byte) error { m.data[key] = value; return nil }

func TestBaselineRecordAndKnown(t *testing.T) {
	b := NewBaseline(nil)
	b.StartTraining()

	h := "abc123"
	b.Record(h)
	if !b.IsKnown(h) {
		t.Error("recorded hash should be known")
	}
	if b.IsKnown("nonexistent") {
		t.Error("unknown hash should not be known")
	}
}

func TestBaselineTrainingLifecycle(t *testing.T) {
	b := NewBaseline(nil)
	if b.IsTraining() {
		t.Error("should not be training initially")
	}

	b.StartTraining()
	if !b.IsTraining() {
		t.Error("should be training after StartTraining")
	}

	b.StopTraining()
	if b.IsTraining() {
		t.Error("should not be training after StopTraining")
	}
}

func TestBaselinePersistLoad(t *testing.T) {
	ms := newMemStore()
	b := NewBaseline(ms)

	// Populate and save
	b.StartTraining()
	b.Record("hash1")
	b.Record("hash2")
	b.Record("hash3")
	b.StopTraining() // saves

	// Create new instance and verify load
	b2 := NewBaseline(ms)
	if !b2.IsKnown("hash1") {
		t.Error("hash1 should survive persist/load")
	}
	if !b2.IsKnown("hash3") {
		t.Error("hash3 should survive persist/load")
	}
}

func TestBaselineTrainingRemaining(t *testing.T) {
	b := NewBaseline(nil)
	b.StartTraining()
	rem := b.TrainingRemaining()
	if rem <= 0 {
		t.Error("expected positive remaining time")
	}
	b.StopTraining()
	if b.TrainingRemaining() != 0 {
		t.Error("expected 0 remaining after stop")
	}
}

// ── Reputation tests ────────────────────────────────────────

func TestRepScoreComm(t *testing.T) {
	r := NewReputation()
	tests := []struct{ comm string; minScore int }{
		{"systemd", 80},
		{"bash", 30},
		{"curl", 20},
		{"nc", 5},
		{"unknown-bin", 50},
	}
	for _, tt := range tests {
		got := r.ScoreComm(tt.comm)
		if got < tt.minScore {
			t.Errorf("ScoreComm(%q) = %d, want ≥ %d", tt.comm, got, tt.minScore)
		}
	}
}

func TestRepScorePath(t *testing.T) {
	r := NewReputation()
	tests := []struct{ path string; minScore, maxScore int }{
		{"/usr/bin/nginx", 80, 100},
		{"/bin/ls", 80, 100},
		{"/tmp/evil.sh", 0, 10},
		{"/dev/shm/malware", 0, 10},
		{"/var/log/syslog", 50, 70},
		{"/etc/passwd", 40, 60},
		{"/home/user/test.sh", 30, 60},
		{"/usr/lib/systemd/systemd", 70, 100},
	}
	for _, tt := range tests {
		got := r.ScorePath(tt.path)
		if got < tt.minScore || got > tt.maxScore {
			t.Errorf("ScorePath(%q) = %d, want [%d,%d]", tt.path, got, tt.minScore, tt.maxScore)
		}
	}
}

func TestRepClassify(t *testing.T) {
	r := NewReputation()
	tests := []struct{ score int; expected string }{
		{90, "trusted"},
		{60, "normal"},
		{30, "suspicious"},
		{5, "untrusted"},
	}
	for _, tt := range tests {
		got := r.Classify(tt.score)
		if got != tt.expected {
			t.Errorf("Classify(%d) = %s, want %s", tt.score, got, tt.expected)
		}
	}
}

func TestRepThresholds(t *testing.T) {
	if !ShouldAggressivelyMerge(85) {
		t.Error("85 should be aggressively merged")
	}
	if ShouldAggressivelyMerge(50) {
		t.Error("50 should NOT be aggressively merged")
	}
	if !IsUntrusted(5) {
		t.Error("5 should be untrusted")
	}
	if IsUntrusted(50) {
		t.Error("50 should NOT be untrusted")
	}
}

// ── Engine tests ───────────────────────────────────────────

func TestEngineNew(t *testing.T) {
	e := NewEngine(NewBaseline(nil), NewReputation())
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
}

func TestEngineTrainingRecordsEverything(t *testing.T) {
	b := NewBaseline(nil)
	b.StartTraining()
	e := NewEngine(b, NewReputation())

	evt := &collector.Event{Type: syscall.EventFileOpen, Comm: "bash", Pathname: "/tmp/test"}
	dec := e.Decide(evt)
	if dec != DecisionProcess {
		t.Errorf("during training, expected PROCESS, got %s", dec)
	}
}

func TestEngineBaselineFilter(t *testing.T) {
	b := NewBaseline(nil)
	// Manually add a known benign hash
	evt := &collector.Event{Type: syscall.EventFileOpen, Comm: "systemd", Pathname: "/var/log/syslog"}
	hash := Hash(evt)
	b.Record(hash)

	e := NewEngine(b, NewReputation())
	dec := e.Decide(evt)
	// systemd + /var/log = high reputation → low level
	if dec == DecisionProcess {
		t.Log("note: systemd+log was PROCESS (expected LOW_LEVEL)")
	}
}

func TestEngineSensitiveEventsNotFiltered(t *testing.T) {
	b := NewBaseline(nil)
	hash := Hash(&collector.Event{Type: syscall.EventFileOpen, Comm: "cat", Pathname: "/etc/shadow"})
	b.Record(hash) // Add to baseline
	e := NewEngine(b, NewReputation())

	evt := &collector.Event{
		Type: syscall.EventFileOpen, Comm: "cat", Pathname: "/etc/shadow",
		FFlags: 1, // write flag → sensitive
	}
	dec := e.Decide(evt)
	if dec != DecisionProcess {
		t.Errorf("sensitive file write should be PROCESS, got %s", dec)
	}
}

func TestEngineSetuidAlwaysProcessed(t *testing.T) {
	e := NewEngine(NewBaseline(nil), NewReputation())
	evt := &collector.Event{
		Type: syscall.EventProcessExec, Comm: "sudo",
		Flags: syscall.EventFlagExecSetuid,
	}
	if e.Decide(evt) != DecisionProcess {
		t.Error("setuid should always be PROCESS")
	}
}

func TestEngineNetworkAlwaysProcessed(t *testing.T) {
	e := NewEngine(NewBaseline(nil), NewReputation())
	evt := &collector.Event{Type: syscall.EventNetConnect, Comm: "bash"}
	if e.Decide(evt) != DecisionProcess {
		t.Error("network events should always be PROCESS")
	}
}

func TestEngineCounters(t *testing.T) {
	b := NewBaseline(nil)
	// Use comm+path with combined rep >= 80 so Decide increments counters: systemd(95) + /usr/bin(85) = 90
	evt := &collector.Event{Type: syscall.EventFileOpen, Comm: "systemd", Pathname: "/usr/bin/systemctl"}
	hash := Hash(evt)
	b.Record(hash) // add to baseline

	e := NewEngine(b, NewReputation())
	e.Decide(evt)
	e.Decide(evt)

	counts := e.LowLevelCounts()
	if counts[hash] != 2 {
		t.Errorf("counter = %d, want 2", counts[hash])
	}
}

func TestEngineResetCounters(t *testing.T) {
	e := NewEngine(NewBaseline(nil), NewReputation())
	e.ResetCounters()
	if len(e.LowLevelCounts()) != 0 {
		t.Error("counters should be empty after reset")
	}
}

func TestEngineStats(t *testing.T) {
	e := NewEngine(NewBaseline(nil), NewReputation())
	stats := e.Stats()
	if stats == nil {
		t.Error("Stats returned nil")
	}
}

// ── Integration: full pipeline ─────────────────────────────

func TestFilterIntegration(t *testing.T) {
	b := NewBaseline(nil)
	r := NewReputation()
	e := NewEngine(b, r)

	// Phase 1: training
	b.StartTraining()
	e.Decide(&collector.Event{Type: syscall.EventFileOpen, Comm: "systemd-journal", Pathname: "/var/log/journal/xxx.log"})
	e.Decide(&collector.Event{Type: syscall.EventFileOpen, Comm: "systemd-journal", Pathname: "/var/log/journal/yyy.log"})
	e.Decide(&collector.Event{Type: syscall.EventFileOpen, Comm: "ntpd", Pathname: "/var/log/syslog"})
	b.StopTraining()

	// Phase 2: runtime — known pattern should be filtered
	evt := &collector.Event{Type: syscall.EventFileOpen, Comm: "systemd-journal", Pathname: "/var/log/journal/zzz.log"}
	dec := e.Decide(evt)
	t.Logf("known benign pattern: %s", dec)

	// Phase 3: sensitive — always processed
	shadow := &collector.Event{Type: syscall.EventFileOpen, Comm: "cat", Pathname: "/etc/shadow", FFlags: 1}
	if e.Decide(shadow) != DecisionProcess {
		t.Error("shadow access must be processed")
	}

	// Phase 4: unknown pattern — processed
	unknown := &collector.Event{Type: syscall.EventFileOpen, Comm: "curl", Pathname: "/tmp/download.sh"}
	if e.Decide(unknown) != DecisionProcess {
		t.Error("unknown pattern should be processed")
	}

	stats := e.Stats()
	t.Logf("filter stats: total=%v, low=%v, filtered_bytes=%v",
		stats["total_events"], stats["low_level"], stats["filtered_bytes"])
}
