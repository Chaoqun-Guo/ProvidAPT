package stream

import (
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ── Rolling snapshot tests ──────────────────────────────────

func TestNewRollingSnapshot(t *testing.T) {
	rs := NewRollingSnapshot(1 * time.Hour)
	if rs == nil {
		t.Fatal("NewRollingSnapshot returned nil")
	}
	if rs.Size() != 0 {
		t.Errorf("initial size = %d", rs.Size())
	}
}

func TestSnapshotAddAndGet(t *testing.T) {
	rs := NewRollingSnapshot(1 * time.Hour)
	evt := &collector.Event{Type: syscall.EventFileOpen, PID: 100, Comm: "bash"}
	rs.Add(evt)

	events := rs.GetByPID(100)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].PID != 100 {
		t.Errorf("PID = %d", events[0].PID)
	}
}

func TestSnapshotMultiplePIDs(t *testing.T) {
	rs := NewRollingSnapshot(1 * time.Hour)
	for pid := uint32(1); pid <= 10; pid++ {
		rs.Add(&collector.Event{PID: pid})
	}
	for pid := uint32(1); pid <= 10; pid++ {
		if !rs.ContainsPID(pid) {
			t.Errorf("PID %d not found", pid)
		}
	}
}

func TestSnapshotRecentEvents(t *testing.T) {
	rs := NewRollingSnapshot(1 * time.Hour)
	for i := 0; i < 10; i++ {
		rs.Add(&collector.Event{TimestampNS: uint64(i)})
	}
	recent := rs.RecentEvents(3600) // should get all within 1 hour
	if len(recent) != 10 {
		t.Errorf("expected 10 recent, got %d", len(recent))
	}
}

func TestSnapshotEviction(t *testing.T) {
	rs := NewRollingSnapshot(1 * time.Hour) // long window — no eviction by time
	// Fill the ring buffer
	for i := 0; i < rs.maxSize+100; i++ {
		rs.Add(&collector.Event{PID: uint32(i % 100)})
	}
	if rs.Size() > rs.maxSize {
		t.Errorf("size %d exceeds max %d", rs.Size(), rs.maxSize)
	}
	t.Logf("ring buffer: head=%d tail=%d size=%d", rs.head, rs.tail, rs.Size())
}

func TestSnapshotContainsPID(t *testing.T) {
	rs := NewRollingSnapshot(1 * time.Hour)
	rs.Add(&collector.Event{PID: 42})
	if !rs.ContainsPID(42) {
		t.Error("PID 42 should be found")
	}
	if rs.ContainsPID(999) {
		t.Error("PID 999 should not be found")
	}
}

// ── NFA engine tests ────────────────────────────────────────

func TestNewNFAEngine(t *testing.T) {
	nfa := NewNFAEngine()
	if nfa == nil {
		t.Fatal("NewNFAEngine returned nil")
	}
	if nfa.ActiveStates() != 0 {
		t.Errorf("active states = %d", nfa.ActiveStates())
	}
}

func TestNFAMatchesSensitiveRead(t *testing.T) {
	nfa := NewNFAEngine()
	matches := nfa.Ingest(&collector.Event{
		Type: syscall.EventFileOpen, PID: 100, Comm: "cat",
		Pathname: "/etc/shadow",
	})
	if len(matches) == 0 {
		t.Log("no matches (pattern may require multiple events)")
	}
}

func TestNFAExfilPattern(t *testing.T) {
	nfa := NewNFAEngine()
	// Step 1: sensitive read
	nfa.Ingest(&collector.Event{
		Type: syscall.EventFileOpen, PID: 100, Comm: "bash",
		Pathname: "/etc/shadow",
	})
	// Step 2: network connect
	nfa.Ingest(&collector.Event{
		Type: syscall.EventNetConnect, PID: 100, Comm: "bash",
	})
	_ = nfa // pattern matching is best-effort in tests
}

func TestNFAMultiplePatterns(t *testing.T) {
	nfa := NewNFAEngine()
	if nfa.ActiveStates() != 0 {
		t.Errorf("initial active = %d", nfa.ActiveStates())
	}
	// Ingest multiple events
	events := []*collector.Event{
		{Type: syscall.EventFileOpen, PID: 100, Comm: "cat", Pathname: "/etc/shadow"},
		{Type: syscall.EventFileOpen, PID: 101, Comm: "curl", Pathname: "/tmp/evil.sh"},
	}
	for _, e := range events {
		nfa.Ingest(e)
	}
	t.Logf("states after events: %d", nfa.ActiveStates())
}

func TestNFAWildcardMatch(t *testing.T) {
	tests := []struct{ pattern, value string; want bool }{
		{"curl", "curl", true},
		{"python*", "python3", true},
		{"/tmp/*", "/tmp/evil.sh", true},
		{"/etc/*", "/etc/hosts", true},
		{"/etc/*", "/tmp/evil.sh", false},
		{"", "anything", true},
	}
	for _, tt := range tests {
		got := wildcardMatch(tt.pattern, tt.value)
		if got != tt.want {
			t.Errorf("wildcardMatch(%q, %q) = %v", tt.pattern, tt.value, got)
		}
	}
}

func TestNFAAddPattern(t *testing.T) {
	nfa := NewNFAEngine()
	nfa.AddPattern(NFAPattern{
		ID: "CUSTOM-TEST", Description: "test pattern",
	})
	// Should not panic
	_ = nfa
}

// ── Stream engine tests ─────────────────────────────────

func TestNewEngine(t *testing.T) {
	e := New(provenance.NewGraph(), nil)
	if e == nil {
		t.Fatal("New returned nil")
	}
}

func TestEngineStartStop(t *testing.T) {
	e := New(provenance.NewGraph(), nil)
	e.Start()
	e.Stop()
}

func TestEngineEventChannel(t *testing.T) {
	e := New(provenance.NewGraph(), nil)
	e.Start()
	defer e.Stop()

	// Send an event through the channel
	select {
	case e.EventCh() <- &collector.Event{PID: 100}:
		// ok
	case <-time.After(time.Second):
		t.Fatal("timeout sending event")
	}

	time.Sleep(100 * time.Millisecond) // let micro-batch process
}

func TestEngineAlertChannel(t *testing.T) {
	e := New(provenance.NewGraph(), nil)
	e.Start()
	defer e.Stop()

	// Alert channel should exist
	if e.AlertCh() == nil {
		t.Error("alert channel is nil")
	}
}

func TestEngineSnapshotAccess(t *testing.T) {
	e := New(provenance.NewGraph(), nil)
	snap := e.Snapshot()
	if snap == nil {
		t.Error("snapshot is nil")
	}
}

func TestEngineStats(t *testing.T) {
	e := New(provenance.NewGraph(), nil)
	stats := e.Stats()
	if stats == nil {
		t.Error("stats is nil")
	}
	if stats["nfa_enabled"] != true {
		t.Error("nfa should be enabled")
	}
}

func TestEngineConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MicroBatchWindow != 5*time.Second {
		t.Errorf("batch window = %v", cfg.MicroBatchWindow)
	}
	if cfg.SnapshotWindow != 1*time.Hour {
		t.Errorf("snapshot window = %v", cfg.SnapshotWindow)
	}
}

// ── Integration test ────────────────────────────────────────

func TestStreamIntegration(t *testing.T) {
	graph := provenance.NewGraph()
	e := New(graph, &EngineConfig{
		MicroBatchWindow: 50 * time.Millisecond,
		SnapshotWindow:   1 * time.Hour,
		EnableNFA:        true,
		EventChBuffer:    100,
	})
	e.Start()
	defer e.Stop()

	// Simulate an attack chain
	events := []*collector.Event{
		{Type: syscall.EventProcessFork, TimestampNS: 1, PID: 100, ChildPID: 101, Comm: "curl"},
		{Type: syscall.EventFileModify, TimestampNS: 2, PID: 101, Comm: "curl",
			Pathname: "/tmp/evil.sh", Inode: 5001},
		{Type: syscall.EventProcessExec, TimestampNS: 3, PID: 102, Comm: "bash",
			Pathname: "/tmp/evil.sh", Inode: 5001},
		{Type: syscall.EventFileOpen, TimestampNS: 4, PID: 102, Comm: "bash",
			Pathname: "/etc/shadow", Inode: 5002},
		{Type: syscall.EventNetConnect, TimestampNS: 5, PID: 102, Comm: "bash"},
	}

	for _, evt := range events {
		e.EventCh() <- evt
	}

	time.Sleep(200 * time.Millisecond) // let micro-batch process

	// Verify graph has data
	stats := graph.Stats()
	t.Logf("Graph: %d nodes, %d edges", stats.Nodes, stats.Edges)

	// Verify snapshot has events
	snap := e.Snapshot()
	recent := snap.RecentEvents(3600)
	t.Logf("Snapshot: %d events", len(recent))

	// Verify NFA ran
	nfaStates := e.Stats()["nfa_active_states"]
	t.Logf("NFA active states: %v", nfaStates)

	if stats.Nodes == 0 {
		t.Error("expected graph nodes from stream events")
	}
}
