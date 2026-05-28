package pipeline

import (
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/internal/syscall"
)

// ── Merger tests ─────────────────────────────────────────────

func TestMergeWindowFirstAdd(t *testing.T) {
	flushed := 0
	mw := NewMergeWindow(5*time.Second, func(e *provenance.Edge) error {
		flushed++
		return nil
	})

	e := &provenance.Edge{
		Source:   "p:1",
		Target:   "f:100",
		Relation: "prov:used",
	}

	merged := mw.TryMerge(e)
	if merged {
		t.Error("first add should NOT be merged")
	}
}

func TestMergeWindowDeduplicates(t *testing.T) {
	flushed := 0
	mw := NewMergeWindow(5*time.Second, func(e *provenance.Edge) error {
		flushed++
		return nil
	})

	e := &provenance.Edge{
		Source:   "p:1",
		Target:   "f:100",
		Relation: "prov:used",
		Count:    1,
	}

	mw.TryMerge(e) // first — not merged
	mw.TryMerge(e) // second — merged
	mw.TryMerge(e) // third — merged

	if mw.Pending() != 1 {
		t.Errorf("pending = %d, want 1", mw.Pending())
	}
}

func TestMergeWindowFlush(t *testing.T) {
	var flushed []*provenance.Edge
	mw := NewMergeWindow(5*time.Second, func(e *provenance.Edge) error {
		flushed = append(flushed, e)
		return nil
	})

	e := &provenance.Edge{
		Source:   "p:1",
		Target:   "f:100",
		Relation: "prov:used",
	}
	mw.TryMerge(e) // first, not merged
	mw.TryMerge(e) // second, merged

	n, err := mw.Flush()
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if n != 1 {
		t.Errorf("flushed %d, want 1", n)
	}
	if len(flushed) != 1 {
		t.Fatalf("callback called %d times, want 1", len(flushed))
	}
	if flushed[0].Count != 2 {
		t.Errorf("count = %d, want 2 (merged)", flushed[0].Count)
	}
	if mw.Pending() != 0 {
		t.Errorf("pending = %d, want 0 after flush", mw.Pending())
	}
}

func TestMergeWindowFlushEmpty(t *testing.T) {
	mw := NewMergeWindow(5*time.Second, func(e *provenance.Edge) error {
		return nil
	})
	n, err := mw.Flush()
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if n != 0 {
		t.Errorf("flushed %d, want 0", n)
	}
}

func TestMergeWindowSeparateEdges(t *testing.T) {
	mw := NewMergeWindow(5*time.Second, func(e *provenance.Edge) error {
		return nil
	})

	// Different edges — both are NOT merged
	mw.TryMerge(&provenance.Edge{Source: "p:1", Target: "f:a", Relation: "prov:used"})
	mw.TryMerge(&provenance.Edge{Source: "p:1", Target: "f:b", Relation: "prov:used"})
	mw.TryMerge(&provenance.Edge{Source: "p:2", Target: "f:a", Relation: "prov:used"})

	if mw.Pending() != 3 {
		t.Errorf("pending = %d, want 3 (different edges)", mw.Pending())
	}
}

// ── Backpressure monitor tests ──────────────────────────────

func TestPressureMonitorCreate(t *testing.T) {
	pm := NewPressureMonitor(4096, nil, nil)
	if pm == nil {
		t.Fatal("NewPressureMonitor returned nil")
	}
	p := pm.Pressure()
	if p < 0 || p > 1 {
		t.Errorf("Pressure() = %f, expected [0,1]", p)
	}
}

func TestPressureMonitorDetectMemory(t *testing.T) {
	mem := detectSystemMemory()
	if mem == 0 {
		t.Error("detectSystemMemory returned 0")
	}
}

// ── Config ─────────────────────────────────────────────────

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxCacheSize <= 0 {
		t.Errorf("MaxCacheSize = %d", cfg.MaxCacheSize)
	}
	if cfg.MergeWindow != 5*time.Second {
		t.Errorf("MergeWindow = %v", cfg.MergeWindow)
	}
	if cfg.FlushInterval <= 0 {
		t.Errorf("FlushInterval = %v", cfg.FlushInterval)
	}
}

// ── Edge derivation from events ────────────────────────────

func TestDeriveEdgesFork(t *testing.T) {
	evt := &collector.Event{
		Type:     syscall.EventProcessFork,
		PID:      100,
		ChildPID: 101,
	}
	edges := deriveEdges(evt)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	e := edges[0]
	if e.Source != "p:101" {
		t.Errorf("source = %s, want p:101", e.Source)
	}
	if e.Target != "p:100" {
		t.Errorf("target = %s, want p:100", e.Target)
	}
	if e.Relation != "prov:wasInformedBy" {
		t.Errorf("relation = %s", e.Relation)
	}
}

func TestDeriveEdgesFileOpen(t *testing.T) {
	evt := &collector.Event{
		Type:     syscall.EventFileOpen,
		PID:      100,
		Pathname: "/etc/shadow",
		Inode:    12345,
		DevMajor: 8,
		DevMinor: 3,
	}
	edges := deriveEdges(evt)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	e := edges[0]
	if e.Source != "p:100" {
		t.Errorf("source = %s, want p:100", e.Source)
	}
	if e.Target != "f:12345:8:3" {
		t.Errorf("target = %s, want f:12345:8:3", e.Target)
	}
	if e.Relation != "prov:used" {
		t.Errorf("relation = %s", e.Relation)
	}
}

func TestDeriveEdgesFileCreate(t *testing.T) {
	evt := &collector.Event{
		Type:     syscall.EventFileCreate,
		PID:      100,
		Pathname: "/tmp/evil.sh",
		Inode:    99999,
		DevMajor: 8,
		DevMinor: 3,
	}
	edges := deriveEdges(evt)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	e := edges[0]
	if e.Source != "f:99999:8:3" {
		t.Errorf("source = %s, want f:99999:8:3", e.Source)
	}
	if e.Target != "p:100" {
		t.Errorf("target = %s, want p:100", e.Target)
	}
	if e.Relation != "prov:wasGeneratedBy" {
		t.Errorf("relation = %s", e.Relation)
	}
}

func TestDeriveEdgesPathOnly(t *testing.T) {
	evt := &collector.Event{
		Type:     syscall.EventFileOpen,
		PID:      100,
		Pathname: "/tmp/test.txt",
		Inode:    0, // no inode — uses path hash
	}
	edges := deriveEdges(evt)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	// ID should be path-hash based
	if !hasPrefix(edges[0].Target, "f:path:") {
		t.Errorf("target = %s, expected f:path:*", edges[0].Target)
	}
}

func TestDeriveEdgesSkipsEmptyPath(t *testing.T) {
	evt := &collector.Event{
		Type:     syscall.EventFileOpen,
		PID:      100,
		Pathname: "?",
	}
	edges := deriveEdges(evt)
	if len(edges) != 0 {
		t.Errorf("expected 0 edges for '?' path, got %d", len(edges))
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
