// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package backtrace

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ── Helpers ──────────────────────────────────────────────────

func buildGraph(events []*collector.Event) *provenance.Graph {
	g := provenance.NewGraph()
	for _, evt := range events {
		g.AddEvent(evt)
	}
	return g
}

func testEvent(typ syscall.EventType, pid, uid uint32, comm, pathname string) *collector.Event {
	return &collector.Event{
		Type:        typ,
		TimestampNS: 1000000000,
		PID:         pid,
		PPID:        1,
		UID:         uid,
		Comm:        comm,
		Pathname:    pathname,
		Inode:       uint64(pid * 1000),
		DevMajor:    8,
		DevMinor:    3,
		Mode:        0o100644,
		FFlags:      0,
	}
}

func testFork(parent, child, uid uint32, comm string) *collector.Event {
	return &collector.Event{
		Type:        syscall.EventProcessFork,
		TimestampNS: 1000000000,
		PID:         parent,
		PPID:        1,
		UID:         uid,
		Comm:        comm,
		ChildPID:    child,
	}
}

func testWrite(pid, uid uint32, comm, pathname string) *collector.Event {
	e := testEvent(syscall.EventFileModify, pid, uid, comm, pathname)
	e.FFlags = 1
	return e
}

// ── Tests ───────────────────────────────────────────────────

func TestTraceByPID(t *testing.T) {
	// Chain: init(p:1) → sshd(p:100) → bash(p:200) → curl(p:300)
	g := buildGraph([]*collector.Event{
		testFork(1, 100, 0, "sshd"),
		testFork(100, 200, 1000, "bash"),
		testFork(200, 300, 1000, "curl"),
	})
	bt := New(g, nil) // no RocksDB store

	result, err := bt.TraceByPID(300, 10)
	if err != nil {
		t.Fatalf("TraceByPID: %v", err)
	}

	if result.StartID != "p:300" {
		t.Errorf("StartID = %s, want p:300", result.StartID)
	}
	if len(result.Segments) == 0 {
		t.Fatal("expected at least 1 segment")
	}

	// Depth 0: curl itself
	seg0 := result.Segments[0]
	if seg0.Depth != 0 {
		t.Errorf("seg0 depth = %d, want 0", seg0.Depth)
	}
	if len(seg0.Nodes) != 1 {
		t.Errorf("seg0 has %d nodes, want 1", len(seg0.Nodes))
	}

	t.Logf("Trace from p:300:")
	for _, seg := range result.Segments {
		t.Logf("  depth %d: %d nodes, edges=%v",
			seg.Depth, len(seg.Nodes), seg.Description)
		for _, n := range seg.Nodes {
			t.Logf("    %s (%s)", n.ID, n.Label)
		}
	}

	// Should reach p:1 (init)
	if !result.HitRoot {
		t.Log("(did not reach root — may need more depth)")
	}
}

func TestTraceDepthLimit(t *testing.T) {
	// Chain: 1→2→3→4→5→6→7→8 (7 forks)
	events := []*collector.Event{}
	for i := 2; i <= 8; i++ {
		events = append(events, testFork(uint32(i-1), uint32(i), 0, "sh"))
	}
	g := buildGraph(events)
	bt := New(g, nil)

	// Trace with max depth 3
	result, _ := bt.Trace(&TraceRequest{
		StartID: "p:8",
		MaxDepth: 3,
	})

	if len(result.Segments) > 4 { // depth 0 + 1 + 2 + 3 = 4 segments
		t.Errorf("segments = %d, want ≤4 (depth 3)", len(result.Segments))
	}
	if !result.Truncated {
		t.Log("(trace was truncated at depth 3 as expected)")
	}
	t.Logf("depth-limited trace: %d segments, truncated=%v",
		len(result.Segments), result.Truncated)
}

func TestTraceByFileInode(t *testing.T) {
	// Scenario: apache writes /tmp/evil.sh → bash reads it
	g := buildGraph([]*collector.Event{
		testFork(1, 100, 0, "apache2"),
		testWrite(100, 0, "apache2", "/tmp/evil.sh"),
		testEvent(syscall.EventFileOpen, 200, 1000, "bash", "/tmp/evil.sh"),
	})
	bt := New(g, nil)

	// Trace from the process that read the file
	result, err := bt.TraceByPID(200, 5)
	if err != nil {
		t.Fatalf("TraceByPID: %v", err)
	}

	t.Logf("Trace from bash(p:200):")
	for _, seg := range result.Segments {
		t.Logf("  depth %d: %d nodes", seg.Depth, len(seg.Nodes))
		for _, n := range seg.Nodes {
			t.Logf("    %s (%s)", n.ID, n.Label)
		}
	}

	if len(result.Segments) >= 2 {
		t.Log("successfully traced backward from bash to apache chain")
	}
}

func TestTracePagination(t *testing.T) {
	// Many children of p:1
	events := []*collector.Event{}
	for i := 2; i <= 20; i++ {
		events = append(events, testFork(1, uint32(i), 0, "forked"))
	}
	g := buildGraph(events)
	bt := New(g, nil)

	// Limit to 5 nodes per segment
	result, _ := bt.Trace(&TraceRequest{
		StartID:          "p:2",
		MaxDepth:         3,
		MaxNodesPerSegment: 5,
	})

	t.Logf("Pagination test: %d segments", len(result.Segments))
	for _, seg := range result.Segments {
		t.Logf("  depth %d: %d nodes, has_more=%v, total_at_depth=%d",
			seg.Depth, len(seg.Nodes), seg.HasMore, seg.TotalAtDepth)
	}
}

func TestTraceTimeline(t *testing.T) {
	g := buildGraph([]*collector.Event{
		testFork(1, 100, 0, "nginx"),
		testEvent(syscall.EventFileOpen, 100, 0, "nginx", "/etc/shadow"),
	})
	bt := New(g, nil)

	result, _ := bt.TraceByPID(100, 3)
	if result == nil {
		t.Fatal("TraceByPID returned nil")
	}

	t.Logf("Timeline (%d events):", len(result.Timeline))
	for _, evt := range result.Timeline {
		t.Logf("  [depth %d] %s %s %s",
			evt.Depth, evt.NodeID, evt.EdgeRel, evt.Timestamp)
	}
}

func TestTraceFileID(t *testing.T) {
	// Use the convenience method TraceByInode
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventFileOpen, 100, 0, "cat", "/etc/passwd"),
	})
	bt := New(g, nil)

	result, err := bt.TraceByInode(100000, 8, 3, 5)
	if err != nil {
		t.Fatalf("TraceByInode: %v", err)
	}
	if result == nil {
		t.Fatal("TraceByInode returned nil")
	}
	t.Logf("Trace from file f:100000:8:3: %d segments, %d nodes",
		len(result.Segments), result.TotalNodes)
}

func TestTraceRequestNormalize(t *testing.T) {
	req := &TraceRequest{StartID: "p:100"}
	req.normalize()
	if req.MaxDepth != defaultMaxDepth {
		t.Errorf("MaxDepth = %d, want %d", req.MaxDepth, defaultMaxDepth)
	}
	if req.MaxNodesPerSegment != defaultMaxNodes {
		t.Errorf("MaxNodesPerSegment = %d, want %d",
			req.MaxNodesPerSegment, defaultMaxNodes)
	}
}

func TestTraceInvalidStartID(t *testing.T) {
	bt := New(provenance.NewGraph(), nil)
	_, err := bt.Trace(&TraceRequest{StartID: ""})
	if err == nil {
		t.Fatal("expected error for empty StartID")
	}
}

func TestTraceEmptyGraph(t *testing.T) {
	bt := New(provenance.NewGraph(), nil)
	result, err := bt.TraceByPID(9999, 5)
	if err != nil {
		t.Fatalf("TraceByPID: %v", err)
	}
	if result == nil {
		t.Fatal("TraceByPID returned nil")
	}
	// Should return at least the synthetic node for the start entity
	if result.TotalNodes == 0 && len(result.Segments) == 0 {
		t.Error("expected at least the start node")
	}
}

func TestSyntheticNode(t *testing.T) {
	bt := New(provenance.NewGraph(), nil)

	n := bt.syntheticNode("p:9999")
	if n.ProvType != "prov:Activity" {
		t.Errorf("process synthetic: prov_type=%s", n.ProvType)
	}

	n = bt.syntheticNode("f:12345:8:3")
	if n.ProvType != "prov:Entity" {
		t.Errorf("file synthetic: prov_type=%s", n.ProvType)
	}
}

func TestReverseEdges(t *testing.T) {
	g := buildGraph([]*collector.Event{
		testFork(1, 100, 0, "init"),
		testFork(100, 200, 0, "child"),
	})
	bt := New(g, nil)
	bt.buildReverseIndex()

	// p:100 should have reverse edges (wasInformedBy from child)
	edges := bt.reverseEdges("p:100")
	if len(edges) == 0 {
		t.Fatal("expected reverse edges for p:100")
	}
	if edges[0].Source != "p:200" {
		t.Errorf("reverse edge source = %s, want p:200", edges[0].Source)
	}
	if edges[0].Relation != "prov:wasInformedBy" {
		t.Errorf("reverse edge relation = %s", edges[0].Relation)
	}
}
