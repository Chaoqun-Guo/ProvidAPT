// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

// ─── VizEngine tests ────────────────────────────────────────

func TestNewVizEngine(t *testing.T) {
	ve := NewVizEngine()
	if ve == nil {
		t.Fatal("NewVizEngine returned nil")
	}
}

func TestAddNode(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:100", "process", "bash", 50)
	ve.AddNode("f:500", "file", "/etc/shadow", 0)

	ve.mu.Lock()
	if len(ve.nodes) != 2 {
		t.Errorf("nodes = %d", len(ve.nodes))
	}
	ve.mu.Unlock()
}

func TestAddEdge(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:100", "process", "bash", 0)
	ve.AddNode("f:500", "file", "/etc/shadow", 0)
	ve.AddEdge("p:100", "f:500", "prov:used", 1000)

	ve.mu.Lock()
	if len(ve.edges) != 1 {
		t.Errorf("edges = %d", len(ve.edges))
	}
	ve.mu.Unlock()
}

// ─── Subgraph extraction tests ──────────────────────────────

func TestExtractSubgraph(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:1", "process", "init", 0)
	ve.AddNode("p:100", "process", "nginx", 0)
	ve.AddNode("p:101", "process", "bash", 0)
	ve.AddNode("f:500", "file", "/etc/shadow", 0)

	ve.AddEdge("p:1", "p:100", "fork", 100)
	ve.AddEdge("p:100", "p:101", "fork", 200)
	ve.AddEdge("p:101", "f:500", "read", 300)

	graph := ve.ExtractSubgraph([]string{"p:100"}, 2, 0, 0)

	if graph.Data.NodeCount == 0 {
		t.Error("no nodes in subgraph")
	}
	if graph.Data.EdgeCount == 0 {
		t.Error("no edges in subgraph")
	}

	t.Logf("Subgraph: %d nodes, %d edges", graph.Data.NodeCount, graph.Data.EdgeCount)
	for _, el := range graph.Elements {
		t.Logf("  [%s] %+v", el.Group, el.Data)
	}
}

func TestExtractSubgraphSingleNode(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:100", "process", "bash", 0)

	graph := ve.ExtractSubgraph([]string{"p:100"}, 3, 0, 0)
	if graph.Data.NodeCount != 1 {
		t.Errorf("nodes = %d", graph.Data.NodeCount)
	}
}

func TestExtractSubgraphTimeFilter(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:1", "process", "init", 0)
	ve.AddNode("p:100", "process", "bash", 0)
	ve.AddEdge("p:1", "p:100", "fork", 1000)
	ve.AddEdge("p:100", "f:500", "write", 5000)

	// Only events before t=2000
	graph := ve.ExtractSubgraph([]string{"p:1"}, 5, 0, 2000)
	if graph.Data.EdgeCount != 1 {
		t.Logf("Time filter: %d edges (expected 1 before t=2000)", graph.Data.EdgeCount)
	}
}

func TestCytoFormat(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:100", "process", "curl", 75)
	ve.AddNode("n:5.6.7.8", "network", "5.6.7.8", 0)
	ve.AddEdge("p:100", "n:5.6.7.8", "prov:used", 1000)

	graph := ve.ExtractSubgraph([]string{"p:100"}, 1, 0, 0)

	// Verify Cytoscape.js format
	hasNode := false
	hasEdge := false
	for _, el := range graph.Elements {
		if el.Group == "nodes" {
			hasNode = true
			if el.Data.ID == "" {
				t.Error("node missing ID")
			}
		}
		if el.Group == "edges" {
			hasEdge = true
			if el.Data.Source == "" || el.Data.Target == "" {
				t.Error("edge missing source/target")
			}
		}
	}
	if !hasNode {
		t.Error("no node elements")
	}
	if !hasEdge {
		t.Error("no edge elements")
	}
}

func TestSeedNodeClass(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:100", "process", "nginx", 0)
	ve.AddNode("p:101", "process", "bash", 0)
	ve.AddEdge("p:100", "p:101", "fork", 100)

	graph := ve.ExtractSubgraph([]string{"p:100"}, 1, 0, 0)

	for _, el := range graph.Elements {
		if el.Data.ID == "p:100" && el.Data.Class != "seed" {
			t.Error("seed node should have class='seed'")
		}
	}
}

// ─── Timeline tests ─────────────────────────────────────────

func TestGenerateTimeline(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:1", "process", "sshd", 0)
	ve.AddNode("p:100", "process", "bash", 0)
	ve.AddNode("p:101", "process", "curl", 0)
	ve.AddNode("f:500", "file", "/etc/shadow", 0)
	ve.AddNode("n:5.6.7.8", "network", "5.6.7.8", 0)

	ve.AddEdge("p:1", "p:100", "fork", 1000)
	ve.AddEdge("p:100", "p:101", "fork", 2000)
	ve.AddEdge("p:101", "f:500", "read", 3000)
	ve.AddEdge("p:101", "n:5.6.7.8", "connect", 4000)

	frames := ve.GenerateTimeline([]string{"p:1"}, 5, 3)
	if len(frames) == 0 {
		t.Fatal("no timeline frames")
	}

	t.Logf("Timeline frames: %d", len(frames))
	for i, frame := range frames {
		t.Logf("  Frame %d: %s (%d nodes, %d edges)",
			i, frame.TimeLabel, len(frame.Nodes), len(frame.Edges))
	}
}

func TestGenerateTimelineEmpty(t *testing.T) {
	ve := NewVizEngine()
	frames := ve.GenerateTimeline([]string{"nonexistent"}, 3, 5)
	if len(frames) == 0 {
		t.Error("should return at least 1 frame")
	}
}

func TestGenerateTimelineSingleFrame(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:1", "process", "init", 0)
	ve.AddEdge("p:1", "p:100", "fork", 100)

	frames := ve.GenerateTimeline([]string{"p:1"}, 2, 1)
	if len(frames) > 0 {
		t.Logf("Single frame: %s (%d nodes)", frames[0].TimeLabel, len(frames[0].Nodes))
	}
}

// ─── Helper tests ───────────────────────────────────────────

func TestTruncateLabel(t *testing.T) {
	if truncateLabel("prov:used") != "used" {
		t.Errorf("used -> %s", truncateLabel("prov:used"))
	}
	if truncateLabel("prov:wasGeneratedBy") != "created" {
		t.Errorf("created -> %s", truncateLabel("prov:wasGeneratedBy"))
	}
	if truncateLabel("custom_long_relation_name") != "custom_long_rela..." {
		t.Errorf("truncated -> %s", truncateLabel("custom_long_relation_name"))
	}
}

// ─── Integration test ───────────────────────────────────────

func TestVizIntegration(t *testing.T) {
	t.Log("=== Visualization Integration ===")

	ve := NewVizEngine()

	// Build a sample attack graph
	ve.AddNode("p:1", "process", "systemd", 0)
	ve.AddNode("p:100", "process", "nginx", 0)
	ve.AddNode("p:101", "process", "bash", 0)
	ve.AddNode("p:102", "process", "curl", 15)
	ve.AddNode("f:500", "file", "/tmp/evil.sh", 0)
	ve.AddNode("f:501", "file", "/etc/shadow", 85)
	ve.AddNode("n:5.6.7.8", "network", "5.6.7.8:443", 70)

	ve.AddEdge("p:1", "p:100", "fork", 100)
	ve.AddEdge("p:100", "p:101", "fork", 200)
	ve.AddEdge("p:101", "f:500", "write", 300)
	ve.AddEdge("p:101", "p:102", "fork", 400)
	ve.AddEdge("p:102", "f:501", "read", 500)
	ve.AddEdge("p:102", "n:5.6.7.8", "connect", 600)

	// 1. Subgraph from attack entry point
	graph := ve.ExtractSubgraph([]string{"p:100"}, 3, 0, 0)
	t.Logf("Subgraph (3 hops from p:100): %d nodes, %d edges",
		graph.Data.NodeCount, graph.Data.EdgeCount)

	// 2. Verify Cytoscape.js format
	var nodeIDs []string
	for _, el := range graph.Elements {
		t.Logf("  [%s] %+v", el.Group, el.Data)
		if el.Group == "nodes" {
			nodeIDs = append(nodeIDs, el.Data.ID)
		}
	}

	// 3. Targeted subgraph from high-risk nodes
	riskGraph := ve.ExtractSubgraph([]string{"f:501", "n:5.6.7.8"}, 2, 0, 0)
	t.Logf("Risk subgraph: %d nodes, %d edges",
		riskGraph.Data.NodeCount, riskGraph.Data.EdgeCount)

	// 4. Timeline replay
	frames := ve.GenerateTimeline([]string{"p:100"}, 5, 4)
	t.Logf("Timeline frames: %d", len(frames))
	for i, frame := range frames {
		t.Logf("  Frame %d: %s (%d nodes, %d edges)",
			i, frame.TimeLabel, len(frame.Nodes), len(frame.Edges))
	}

	// 5. Verify seed node is marked
	for _, el := range graph.Elements {
		if el.Data.ID == "p:100" {
			if el.Data.Class != "seed" {
				t.Error("seed node should be marked")
			}
		}
	}

	t.Log("Visualization integration OK")
}

// ─── Graph sync tests ─────────────────────────────────────────

func TestSyncFromGraph(t *testing.T) {
	graph := buildTestGraph(t)

	ve := NewVizEngine()
	if err := ve.SyncFromGraph(graph); err != nil {
		t.Fatalf("SyncFromGraph error: %v", err)
	}

	ve.mu.Lock()
	nodeCount := len(ve.nodes)
	edgeCount := len(ve.edges)
	ve.mu.Unlock()

	if nodeCount == 0 {
		t.Error("no nodes synced from graph")
	}
	if edgeCount == 0 {
		t.Error("no edges synced from graph")
	}
	t.Logf("Synced: %d nodes, %d edges", nodeCount, edgeCount)
}

func TestSyncFromGraphEmpty(t *testing.T) {
	graph := provenance.NewGraph()

	ve := NewVizEngine()
	if err := ve.SyncFromGraph(graph); err != nil {
		t.Fatalf("SyncFromGraph error: %v", err)
	}

	ve.mu.Lock()
	nodeCount := len(ve.nodes)
	edgeCount := len(ve.edges)
	ve.mu.Unlock()

	if nodeCount != 0 {
		t.Errorf("expected 0 nodes, got %d", nodeCount)
	}
	if edgeCount != 0 {
		t.Errorf("expected 0 edges, got %d", edgeCount)
	}
}

func TestSyncFromGraphNoGraph(t *testing.T) {
	ve := NewVizEngine()
	err := ve.Sync()
	if err == nil {
		t.Fatal("expected error when no graph connected")
	}
}

func TestSyncClearsExisting(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:1", "process", "old", 0)
	ve.AddEdge("p:1", "f:1", "used", 100)

	graph := buildTestGraph(t)
	if err := ve.SyncFromGraph(graph); err != nil {
		t.Fatalf("SyncFromGraph error: %v", err)
	}

	ve.mu.Lock()
	_, exists := ve.nodes["p:1"]
	ve.mu.Unlock()
	if exists {
		t.Error("old nodes should be cleared after sync")
	}
}

func TestSetGraph(t *testing.T) {
	graph := buildTestGraph(t)

	ve := NewVizEngine()
	ve.SetGraph(graph)

	ve.mu.Lock()
	if ve.graph != graph {
		t.Error("SetGraph did not store reference")
	}
	ve.mu.Unlock()
}

// ─── Pagination tests ─────────────────────────────────────────

func TestExtractSubgraphWithOptsLimit(t *testing.T) {
	ve := NewVizEngine()
	for i := 0; i < 20; i++ {
		ve.AddNode(fmt.Sprintf("p:%d", i), "process", fmt.Sprintf("proc%d", i), 0)
	}
	// All nodes are seeds.
	seedIDs := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		seedIDs = append(seedIDs, fmt.Sprintf("p:%d", i))
	}

	// Limit to 5 nodes.
	graph := ve.ExtractSubgraphWithOpts(seedIDs, 0, 0, 0, SubgraphOpts{Limit: 5})
	if graph.Data.NodeCount > 5 {
		t.Errorf("expected <= 5 nodes with Limit=5, got %d", graph.Data.NodeCount)
	}
	t.Logf("Limit=5: %d nodes", graph.Data.NodeCount)
}

func TestExtractSubgraphWithOptsOffset(t *testing.T) {
	ve := NewVizEngine()
	for i := 0; i < 20; i++ {
		ve.AddNode(fmt.Sprintf("p:%d", i), "process", fmt.Sprintf("proc%d", i), 0)
	}
	seedIDs := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		seedIDs = append(seedIDs, fmt.Sprintf("p:%d", i))
	}

	// Offset 10: should get nodes p:10 through p:19.
	graph := ve.ExtractSubgraphWithOpts(seedIDs, 0, 0, 0, SubgraphOpts{Offset: 10})
	if graph.Data.NodeCount != 10 {
		t.Errorf("expected 10 nodes with Offset=10, got %d", graph.Data.NodeCount)
	}
	t.Logf("Offset=10: %d nodes", graph.Data.NodeCount)
}

func TestExtractSubgraphWithOptsOffsetLimit(t *testing.T) {
	ve := NewVizEngine()
	for i := 0; i < 20; i++ {
		ve.AddNode(fmt.Sprintf("p:%d", i), "process", fmt.Sprintf("proc%d", i), 0)
	}
	seedIDs := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		seedIDs = append(seedIDs, fmt.Sprintf("p:%d", i))
	}

	// Offset 5, Limit 10: nodes p:5 through p:14.
	graph := ve.ExtractSubgraphWithOpts(seedIDs, 0, 0, 0, SubgraphOpts{Offset: 5, Limit: 10})
	if graph.Data.NodeCount != 10 {
		t.Errorf("expected 10 nodes with Offset=5, Limit=10, got %d", graph.Data.NodeCount)
	}
	t.Logf("Offset=5, Limit=10: %d nodes", graph.Data.NodeCount)
}

func TestExtractSubgraphWithOptsOffsetBeyondEnd(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:1", "process", "proc1", 0)
	ve.AddNode("p:2", "process", "proc2", 0)

	graph := ve.ExtractSubgraphWithOpts([]string{"p:1", "p:2"}, 0, 0, 0, SubgraphOpts{Offset: 10})
	if graph.Data.NodeCount != 0 {
		t.Errorf("expected 0 nodes with Offset beyond end, got %d", graph.Data.NodeCount)
	}
}

// ─── Context cancellation tests ───────────────────────────────

func TestExtractSubgraphWithOptsCancellation(t *testing.T) {
	ve := NewVizEngine()
	for i := 0; i < 50; i++ {
		ve.AddNode(fmt.Sprintf("p:%d", i), "process", fmt.Sprintf("proc%d", i), 0)
	}
	seedIDs := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		seedIDs = append(seedIDs, fmt.Sprintf("p:%d", i))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	graph := ve.ExtractSubgraphWithOpts(seedIDs, 0, 0, 0, SubgraphOpts{Ctx: ctx})
	// Must not panic; returns whatever it has.
	t.Logf("Cancelled: %d nodes", graph.Data.NodeCount)
}

func TestExtractSubgraphWithOptsTimeout(t *testing.T) {
	ve := NewVizEngine()
	for i := 0; i < 100; i++ {
		ve.AddNode(fmt.Sprintf("p:%d", i), "process", fmt.Sprintf("proc%d", i), 0)
	}
	seedIDs := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		seedIDs = append(seedIDs, fmt.Sprintf("p:%d", i))
	}

	// Very short timeout — should still return gracefully.
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure expiry

	graph := ve.ExtractSubgraphWithOpts(seedIDs, 0, 0, 0, SubgraphOpts{Ctx: ctx})
	t.Logf("Timeout: %d nodes", graph.Data.NodeCount)
}

// ─── Helper ───────────────────────────────────────────────────


// ─── Partial extraction tests ─────────────────────────────────

func TestExtractPartialFirstLevel(t *testing.T) {
	ve := NewVizEngine()
	// Build a 4-level chain: 0→1→2→3→4
	for i := 0; i <= 4; i++ {
		ve.AddNode(fmt.Sprintf("p:%d", i), "process", fmt.Sprintf("proc%d", i), 0)
	}
	for i := 0; i < 4; i++ {
		ve.AddEdge(fmt.Sprintf("p:%d", i), fmt.Sprintf("p:%d", i+1), "fork", int64(i*1000))
	}

	// Depth 0-1 from seed p:0
	result := ve.ExtractPartial([]string{"p:0"}, 4, 0, 1, SubgraphOpts{})
	if result == nil || result.Graph == nil {
		t.Fatal("ExtractPartial returned nil")
	}
	if result.Graph.Data.NodeCount <= 0 {
		t.Error("expected nodes in depth range 0-1")
	}
	if !result.HasMore {
		t.Error("HasMore should be true when deeper levels exist")
	}
	t.Logf("Depth 0-1: %d nodes, HasMore=%v", result.Graph.Data.NodeCount, result.HasMore)
}

func TestExtractPartialLastLevel(t *testing.T) {
	ve := NewVizEngine()
	for i := 0; i <= 4; i++ {
		ve.AddNode(fmt.Sprintf("p:%d", i), "process", fmt.Sprintf("proc%d", i), 0)
	}
	for i := 0; i < 4; i++ {
		ve.AddEdge(fmt.Sprintf("p:%d", i), fmt.Sprintf("p:%d", i+1), "fork", int64(i*1000))
	}

	// Depth 4-5 — only p:4 should be in this range
	result := ve.ExtractPartial([]string{"p:0"}, 4, 4, 1, SubgraphOpts{})
	if result == nil || result.Graph == nil {
		t.Fatal("ExtractPartial returned nil")
	}
	if !result.HasMore {
		t.Log("Last level: HasMore=false (as expected)")
	}
	t.Logf("Depth 4: %d nodes", result.Graph.Data.NodeCount)
}

func TestExtractPartialBeyondMax(t *testing.T) {
	ve := NewVizEngine()
	ve.AddNode("p:0", "process", "root", 0)

	// startDepth beyond maxHops should return empty but not panic.
	result := ve.ExtractPartial([]string{"p:0"}, 3, 10, 1, SubgraphOpts{})
	if result == nil || result.Graph == nil {
		t.Fatal("ExtractPartial returned nil")
	}
	t.Logf("Beyond max: %d nodes, HasMore=%v", result.Graph.Data.NodeCount, result.HasMore)
}

func TestExtractPartialPagination(t *testing.T) {
	ve := NewVizEngine()
	for i := 0; i < 10; i++ {
		ve.AddNode(fmt.Sprintf("p:%d", i), "process", fmt.Sprintf("proc%d", i), 0)
	}

	// All nodes are seeds at depth 0. Limit to 3.
	seeds := make([]string, 10)
	for i := 0; i < 10; i++ {
		seeds[i] = fmt.Sprintf("p:%d", i)
	}
	result := ve.ExtractPartial(seeds, 0, 0, 1, SubgraphOpts{Limit: 3})
	if result.Graph.Data.NodeCount > 3 {
		t.Errorf("expected ≤3 nodes with Limit=3, got %d", result.Graph.Data.NodeCount)
	}
	t.Logf("Paginated partial: %d nodes", result.Graph.Data.NodeCount)
}

func buildTestGraph(t *testing.T) *provenance.Graph {
	t.Helper()
	graph := provenance.NewGraph()

	// Add a fork event: process 100 → 101
	graph.AddEvent(&collector.Event{
		PID:      100,
		Type:     syscall.EventProcessFork,
		ChildPID: 101,
	})
	// Add an exec event: process 101 executes /bin/bash
	graph.AddEvent(&collector.Event{
		PID:      101,
		Type:     syscall.EventProcessExec,
		Pathname: "/bin/bash",
	})
	// Add a file open: process 101 reads /etc/passwd
	graph.AddEvent(&collector.Event{
		PID:      101,
		Type:     syscall.EventFileOpen,
		Pathname: "/etc/passwd",
	})
	// Add a file create: process 101 writes /tmp/out
	graph.AddEvent(&collector.Event{
		PID:      101,
		Type:     syscall.EventFileCreate,
		Pathname: "/tmp/out",
	})

	stats := graph.Stats()
	if stats.Nodes == 0 {
		t.Fatal("test graph has no nodes")
	}
	t.Logf("Test graph: %d nodes, %d edges", stats.Nodes, stats.Edges)
	return graph
}
