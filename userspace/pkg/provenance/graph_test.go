package provenance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/internal/syscall"
)

// ── Helpers ──────────────────────────────────────────────────

func makeEvent(typ syscall.EventType, pid, ppid, uid uint32, comm, pathname string) *collector.Event {
	return &collector.Event{
		Type:        typ,
		TimestampNS: 1000000000, // 1 sec in monotonic clock
		PID:         pid,
		PPID:        ppid,
		UID:         uid,
		GID:         100,
		Comm:        comm,
		Pathname:    pathname,
		Inode:       uint64(pid * 1000), // deterministic fake inode
		DevMajor:    8,
		DevMinor:    3,
		Mode:        0o100644,
		FFlags:      0, // O_RDONLY
		Flags:       0,
	}
}

func makeWriteEvent(typ syscall.EventType, pid, uid uint32, comm, pathname string) *collector.Event {
	e := makeEvent(typ, pid, 0, uid, comm, pathname)
	e.FFlags = 1 // O_WRONLY
	return e
}

func makeForkEvent(parentPID, childPID, uid uint32, comm string) *collector.Event {
	return &collector.Event{
		Type:        syscall.EventProcessFork,
		TimestampNS: 1000000000,
		PID:         parentPID,
		PPID:        1,
		TID:         parentPID,
		UID:         uid,
		GID:         100,
		Comm:        comm,
		ChildPID:    childPID,
		Pathname:    "",
	}
}

// ── Graph construction ──────────────────────────────────────

func TestGraphNew(t *testing.T) {
	g := NewGraph()
	if g == nil {
		t.Fatal("NewGraph returned nil")
	}
	stats := g.Stats()
	if stats.Nodes != 0 {
		t.Errorf("expected 0 nodes, got %d", stats.Nodes)
	}
	if stats.Edges != 0 {
		t.Errorf("expected 0 edges, got %d", stats.Edges)
	}
}

func TestGraphAddFork(t *testing.T) {
	g := NewGraph()

	// Parent PID=1 forks child PID=2
	g.AddEvent(makeForkEvent(1, 2, 0, "init"))

	stats := g.Stats()
	if stats.Nodes != 2 {
		t.Errorf("expected 2 nodes (parent + child), got %d", stats.Nodes)
	}
	if stats.Edges != 1 {
		t.Errorf("expected 1 edge (wasInformedBy), got %d", stats.Edges)
	}

	// Verify node types
	nodes := g.Nodes()
	var parentFound, childFound bool
	for _, n := range nodes {
		if n.ProvType != ProvActivity {
			t.Errorf("node %s: expected ProvType=prov:Activity, got %s",
				n.ID, n.ProvType)
		}
		if n.Subtype != SubProcess {
			t.Errorf("node %s: expected Subtype=process, got %s",
				n.ID, n.Subtype)
		}
		if n.ID == "p:1" {
			parentFound = true
		}
		if n.ID == "p:2" {
			childFound = true
		}
	}
	if !parentFound {
		t.Error("parent node p:1 not found")
	}
	if !childFound {
		t.Error("child node p:2 not found")
	}

	// Verify edge
	edges := g.Edges()
	if len(edges) != 1 {
		t.Fatal("expected 1 edge")
	}
	e := edges[0]
	if e.Relation != ProvWasInformedBy {
		t.Errorf("expected relation wasInformedBy, got %s", e.Relation)
	}
	if e.Source != "p:2" {
		t.Errorf("expected source p:2 (child), got %s", e.Source)
	}
	if e.Target != "p:1" {
		t.Errorf("expected target p:1 (parent), got %s", e.Target)
	}
}

func TestGraphAddFileOpen(t *testing.T) {
	g := NewGraph()

	evt := makeEvent(syscall.EventFileOpen, 100, 1, 1000, "cat", "/etc/passwd")
	g.AddEvent(evt)

	stats := g.Stats()
	if stats.Nodes != 2 { // process + file
		t.Errorf("expected 2 nodes, got %d", stats.Nodes)
	}
	if stats.Edges != 1 {
		t.Errorf("expected 1 edge (used), got %d", stats.Edges)
	}

	edges := g.Edges()
	if edges[0].Relation != ProvUsed {
		t.Errorf("expected used, got %s", edges[0].Relation)
	}
}

func TestGraphAddFileWrite(t *testing.T) {
	g := NewGraph()

	evt := makeWriteEvent(syscall.EventFileModify, 200, 1000, "vim", "/tmp/notes.txt")
	g.AddEvent(evt)

	edges := g.Edges()
	if len(edges) != 1 {
		t.Fatal("expected 1 edge")
	}
	e := edges[0]
	if e.Relation != ProvWasGeneratedBy {
		t.Errorf("expected wasGeneratedBy, got %s", e.Relation)
	}
	// wasGeneratedBy direction: entity → activity, so source=file, target=process
	if !strings.HasPrefix(e.Source, "f:") {
		t.Errorf("expected source to be file node, got %s", e.Source)
	}
	if e.Target != "p:200" {
		t.Errorf("expected target p:200, got %s", e.Target)
	}
}

func TestGraphDeduplicateNodes(t *testing.T) {
	g := NewGraph()

	// Same process opens two files
	g.AddEvent(makeEvent(syscall.EventFileOpen, 100, 1, 1000, "cat", "/etc/hosts"))
	g.AddEvent(makeEvent(syscall.EventFileOpen, 100, 1, 1000, "cat", "/etc/resolv.conf"))

	stats := g.Stats()
	if stats.Nodes != 3 { // 1 process + 2 files
		t.Errorf("expected 3 nodes (deduplicated process), got %d", stats.Nodes)
	}
	if stats.Edges != 2 {
		t.Errorf("expected 2 edges, got %d", stats.Edges)
	}
}

func TestGraphDeduplicateEdges(t *testing.T) {
	g := NewGraph()

	// Same file read multiple times → edge count increases, not new edges
	evt := makeEvent(syscall.EventFileOpen, 100, 1, 1000, "cat", "/etc/config")
	g.AddEvent(evt)
	g.AddEvent(evt) // duplicate

	stats := g.Stats()
	if stats.Edges != 1 {
		t.Errorf("expected 1 deduplicated edge, got %d", stats.Edges)
	}
	edges := g.Edges()
	if edges[0].Count != 2 {
		t.Errorf("expected edge count=2, got %d", edges[0].Count)
	}
}

func TestGraphMultipleTypes(t *testing.T) {
	g := NewGraph()

	// Simulate a realistic attack scenario
	// 1. bash forks curl
	g.AddEvent(makeForkEvent(100, 200, 1000, "bash"))
	// 2. curl connects (exec event with binary path)
	g.AddEvent(makeEvent(syscall.EventProcessExec, 200, 100, 1000, "curl", "/usr/bin/curl"))
	// 3. curl reads a sensitive file
	g.AddEvent(makeEvent(syscall.EventFileOpen, 200, 100, 1000, "curl", "/etc/shadow"))
	// 4. curl writes exfil data
	g.AddEvent(makeWriteEvent(syscall.EventFileCreate, 200, 1000, "curl", "/tmp/exfil.dat"))

	stats := g.Stats()
	// Nodes: p:100 (bash), p:200 (curl), f:/usr/bin/curl, f:/etc/shadow, f:/tmp/exfil.dat = 5
	if stats.Nodes != 5 {
		t.Errorf("expected 5 nodes, got %d", stats.Nodes)
	}
	// Edges: wasInformedBy(child→parent), used(curl→binary), used(curl→shadow), wasGeneratedBy(exfil→curl) = 4
	if stats.Edges != 4 {
		t.Errorf("expected 4 edges, got %d", stats.Edges)
	}
}

// ── Serialization ───────────────────────────────────────────

func TestSerializeJSON(t *testing.T) {
	g := NewGraph()
	g.AddEvent(makeForkEvent(1, 2, 0, "init"))
	g.AddEvent(makeEvent(syscall.EventFileOpen, 2, 1, 1000, "cat", "/etc/hostname"))

	var buf bytes.Buffer
	if err := g.SerializeJSON(&buf); err != nil {
		t.Fatalf("SerializeJSON: %v", err)
	}

	// Verify it's valid JSON
	var parsed interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	root := parsed.(map[string]interface{})
	if _, ok := root["prefix"]; !ok {
		t.Error("JSON missing 'prefix'")
	}
	if _, ok := root["activity"]; !ok {
		t.Error("JSON missing 'activity'")
	}
	if _, ok := root["entity"]; !ok {
		t.Error("JSON missing 'entity'")
	}
	if _, ok := root["wasInformedBy"]; !ok {
		t.Error("JSON missing 'wasInformedBy'")
	}
	if _, ok := root["used"]; !ok {
		t.Error("JSON missing 'used'")
	}

	t.Logf("JSON output (%d bytes):\n%s", buf.Len(), buf.String())
}

func TestSerializeGraphML(t *testing.T) {
	g := NewGraph()
	g.AddEvent(makeForkEvent(1, 2, 0, "init"))
	g.AddEvent(makeEvent(syscall.EventFileOpen, 2, 1, 1000, "cat", "/etc/hostname"))

	var buf bytes.Buffer
	if err := g.SerializeGraphML(&buf); err != nil {
		t.Fatalf("SerializeGraphML: %v", err)
	}

	output := buf.String()
	// Must have XML declaration
	if !strings.HasPrefix(output, "<?xml") {
		t.Error("GraphML should start with XML declaration")
	}
	// Must have graphml root
	if !strings.Contains(output, "<graphml") {
		t.Error("GraphML missing <graphml>")
	}
	// Must have nodes
	if !strings.Contains(output, "node") {
		t.Error("GraphML missing nodes")
	}
	// Must have edges
	if !strings.Contains(output, "edge") {
		t.Error("GraphML missing edges")
	}

	t.Logf("GraphML output (%d bytes):\n%s", buf.Len(), output)
}

func TestSerializeEmptyGraph(t *testing.T) {
	g := NewGraph()

	var buf bytes.Buffer
	if err := g.SerializeJSON(&buf); err != nil {
		t.Fatalf("empty JSON: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("empty graph JSON should not be empty")
	}

	buf.Reset()
	if err := g.SerializeGraphML(&buf); err != nil {
		t.Fatalf("empty GraphML: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("empty graph GraphML should not be empty")
	}
}

// ── DAG traversal ───────────────────────────────────────────

func TestWalkFrom(t *testing.T) {
	g := NewGraph()
	g.AddEvent(makeForkEvent(1, 2, 0, "init"))     // child(2) ─→ parent(1)
	g.AddEvent(makeForkEvent(2, 3, 0, "bash"))       // child(3) ─→ parent(2)

	var visited []string
	g.WalkFrom("p:3", func(n *Node, e *Edge, depth int) bool {
		visited = append(visited, n.ID)
		return true
	})

	if len(visited) < 2 {
		t.Errorf("WalkFrom visited %d nodes, expected ≥2", len(visited))
	}
}

// ── Concurrency ─────────────────────────────────────────────

func TestGraphConcurrency(t *testing.T) {
	g := NewGraph()
	done := make(chan bool)

	// Concurrent writers
	go func() {
		for i := 0; i < 100; i++ {
			g.AddEvent(makeEvent(syscall.EventFileOpen,
				uint32(i%10), 1, 1000, "test", "/tmp/file"))
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 100; i++ {
			g.AddEvent(makeForkEvent(uint32(i%5), uint32(i%5+100), 0, "sh"))
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 100; i++ {
			g.Stats()
		}
		done <- true
	}()

	// Wait for all goroutines
	<-done
	<-done
	<-done

	// Should not deadlock
	stats := g.Stats()
	t.Logf("Concurrent test: %d nodes, %d edges", stats.Nodes, stats.Edges)
}

// ── Thread safety (go test -race) ───────────────────────────

func TestGraphRaceFree(t *testing.T) {
	g := NewGraph()

	// Writer
	go func() {
		for i := 0; i < 50; i++ {
			g.AddEvent(makeEvent(syscall.EventFileOpen,
				uint32(i), 1, 1000, "prog", "/path/file"))
		}
	}()

	// Reader
	for i := 0; i < 50; i++ {
		stats := g.Stats()
		_ = g.Nodes()
		_ = g.Edges()
		_ = stats.Nodes + stats.Edges
	}

	// The -race detector should find no races.
	// Without -race, this at least exercises the code paths.
}
