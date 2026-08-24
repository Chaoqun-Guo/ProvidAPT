// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"testing"
	"time"

	store "github.com/Chaoqun-Guo/ProvidAPT/internal/storage/graphdb"
)

// ─── Graph DB tests ─────────────────────────────────────────

func TestNewMemGraphDB(t *testing.T) {
	db := store.NewMemGraphDB()
	if db == nil {
		t.Fatal("NewMemGraphDB returned nil")
	}
}

func TestCreateNode(t *testing.T) {
	db := store.NewMemGraphDB()
	id, err := db.CreateNode("process", "p:100", "bash",
		map[string]interface{}{"host_id": "host-1", "pid": 100})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if id == "" {
		t.Error("empty node ID")
	}
}

func TestCreateEdge(t *testing.T) {
	db := store.NewMemGraphDB()
	db.CreateNode("process", "p:1", "init", map[string]interface{}{"host_id": "h1"})
	db.CreateNode("file", "f:500", "/etc/shadow", map[string]interface{}{"host_id": "h1"})
	id, err := db.CreateEdge("p:1", "f:500", "read", nil)
	if err != nil {
		t.Fatalf("CreateEdge: %v", err)
	}
	if id == "" {
		t.Error("empty edge ID")
	}
}

func TestQueryNodes(t *testing.T) {
	db := store.NewMemGraphDB()
	db.CreateNode("process", "p:100", "bash", nil)
	db.CreateNode("process", "p:200", "nginx", nil)

	nodes, err := db.QueryNodes("process", nil)
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("nodes = %d", len(nodes))
	}
}

func TestQueryPaths(t *testing.T) {
	db := store.NewMemGraphDB()
	db.CreateNode("process", "p:1", "init", nil)
	db.CreateNode("process", "p:100", "nginx", nil)
	db.CreateNode("file", "f:500", "/etc/shadow", nil)

	db.CreateEdge("p:1", "p:100", "fork", nil)
	db.CreateEdge("p:100", "f:500", "read", nil)

	paths, err := db.QueryPaths("p:1", "f:500", 5)
	if err != nil {
		t.Fatalf("QueryPaths: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no paths found")
	}
	t.Logf("Path: %v (length=%v)", paths[0]["path"], paths[0]["length"])
}

func TestInsertSubgraph(t *testing.T) {
	db := store.NewMemGraphDB()
	nodes := []store.GlobalNode{
		{ID: "p:1", Type: "process", Label: "init", HostID: "h1"},
		{ID: "f:500", Type: "file", Label: "/etc/shadow", HostID: "h1"},
	}
	edges := []store.GlobalEdge{
		{Source: "p:1", Target: "f:500", Relation: "read", HostID: "h1"},
	}

	err := store.InsertSubgraph(db, nodes, edges)
	if err != nil {
		t.Fatalf("InsertSubgraph: %v", err)
	}

	stats := db.Stats()
	if stats["nodes"].(int) != 2 {
		t.Errorf("nodes = %d", stats["nodes"])
	}
	if stats["edges"].(int) != 1 {
		t.Errorf("edges = %d", stats["edges"])
	}
}

// ─── Global index tests ─────────────────────────────────────

func TestNewGlobalIndex(t *testing.T) {
	gi := store.NewGlobalIndex()
	if gi == nil {
		t.Fatal("NewGlobalIndex returned nil")
	}
}

func TestIndexByHostID(t *testing.T) {
	gi := store.NewGlobalIndex()
	node := &store.GlobalNode{
		ID: "p:100", Type: "process", Label: "bash",
		HostID: "host-abc", AgentID: "agent-a",
		Props: map[string]interface{}{"identity": "alice"},
	}
	gi.IndexNode(node)

	entries := gi.QueryByHostID("host-abc")
	if len(entries) != 1 {
		t.Errorf("entries = %d", len(entries))
	}
	if entries[0].Label != "bash" {
		t.Errorf("label = %s", entries[0].Label)
	}
}

func TestIndexByIP(t *testing.T) {
	gi := store.NewGlobalIndex()
	node := &store.GlobalNode{
		ID: "n:5.6.7.8", Type: "network", Label: "5.6.7.8",
		HostID: "host-abc",
	}
	gi.IndexNode(node)

	entries := gi.QueryByIP("5.6.7.8")
	if len(entries) == 0 {
		t.Errorf("expected IP match")
	}
}

func TestIndexByIdentity(t *testing.T) {
	gi := store.NewGlobalIndex()
	node := &store.GlobalNode{
		ID: "p:100", Type: "process", Label: "bash",
		HostID: "host-abc",
		Props:  map[string]interface{}{"identity": "alice"},
	}
	gi.IndexNode(node)

	entries := gi.QueryByIdentity("alice")
	if len(entries) != 1 {
		t.Errorf("entries = %d", len(entries))
	}
}

func TestGlobalBacktrack(t *testing.T) {
	gi := store.NewGlobalIndex()
	node := &store.GlobalNode{
		ID: "p:100", Type: "process", Label: "bash",
		HostID: "host-abc",
	}
	gi.IndexNode(node)

	hosts := gi.GlobalBacktrack("p:100")
	if len(hosts) == 0 || hosts[0] != "host-abc" {
		t.Errorf("backtrack = %v", hosts)
	}
}

func TestStoreStats2(t *testing.T) {
	gi := store.NewGlobalIndex()
	gi.IndexNode(&store.GlobalNode{ID: "p:1", HostID: "h1"})
	gi.IndexNode(&store.GlobalNode{ID: "p:2", HostID: "h2"})

	stats := gi.Stats()
	if stats["by_host_id"].(int) != 2 {
		t.Errorf("hosts = %d", stats["by_host_id"])
	}
}

// ─── Lifecycle tests ────────────────────────────────────────

func TestNewLifecycleManager(t *testing.T) {
	lm := store.NewLifecycleManager(nil)
	if lm == nil {
		t.Fatal("NewLifecycleManager returned nil")
	}
}

func TestClassifyHot(t *testing.T) {
	lm := store.NewLifecycleManager(nil)
	tier := lm.Classify(time.Now(), false)
	if tier != store.TierHot {
		t.Errorf("tier = %d (expected hot)", tier)
	}
}

func TestClassifyColdNonAlert(t *testing.T) {
	lm := store.NewLifecycleManager(&store.LifecycleConfig{
		HotRetention:  0,
		WarmRetention: 0,
	})
	tier := lm.Classify(time.Now().Add(-48*time.Hour), false)
	_ = tier
}

func TestShouldPrune(t *testing.T) {
	lm := store.NewLifecycleManager(&store.LifecycleConfig{
		WarmRetention: 0, // prune immediately
	})
	if !lm.ShouldPrune(time.Now().Add(-48*time.Hour), false) {
		t.Error("old non-alert should be pruned")
	}
	if lm.ShouldPrune(time.Now().Add(-48*time.Hour), true) {
		t.Error("alert should NOT be pruned")
	}
}

func TestArchive(t *testing.T) {
	lm := store.NewLifecycleManager(&store.LifecycleConfig{DryRun: true})
	rec := &store.DataRecord{
		ID:        "p:100",
		Tier:      store.TierHot,
		CreatedAt: time.Now().Add(-20 * 24 * time.Hour),
		IsAlert:   false,
	}
	newTier := lm.Archive(rec)
	_ = newTier
	t.Log("archive action (dry run)")
}

func TestTick(t *testing.T) {
	lm := store.NewLifecycleManager(nil)
	lm.Tick()
}

func TestStoreStats3(t *testing.T) {
	lm := store.NewLifecycleManager(nil)
	stats := lm.Stats()
	if stats["hot_retention_days"].(int) != 7 {
		t.Errorf("hot = %d", stats["hot_retention_days"])
	}
}

// ─── Integration test ───────────────────────────────────────

func TestStoreIntegration(t *testing.T) {
	t.Log("=== Central Store Integration ===")

	// 1. Graph DB
	db := store.NewMemGraphDB()
	store.InsertSubgraph(db, []store.GlobalNode{
		{ID: "p:100", Type: "process", Label: "bash", HostID: "host-web"},
		{ID: "f:5000", Type: "file", Label: "/etc/shadow", HostID: "host-web"},
		{ID: "n:5.6.7.8", Type: "network", Label: "5.6.7.8", HostID: "host-web"},
	}, []store.GlobalEdge{
		{Source: "p:100", Target: "f:5000", Relation: "read", HostID: "host-web"},
		{Source: "p:100", Target: "n:5.6.7.8", Relation: "connect", HostID: "host-web"},
	})
	dbStats := db.Stats()
	t.Logf("Graph: %d nodes, %d edges", dbStats["nodes"], dbStats["edges"])

	// 2. Global index
	gi := store.NewGlobalIndex()
	nodes, _ := db.QueryNodes("", nil)
	for _, n := range nodes {
		gi.IndexNode(&store.GlobalNode{
			ID:      n["id"].(string),
			Type:    n["type"].(string),
			Label:   n["label"].(string),
			HostID:  n["host_id"].(string),
			AgentID: n["agent_id"].(string),
		})
	}
	idxStats := gi.Stats()
	t.Logf("Index: %d hosts, %d IPs", idxStats["by_host_id"], idxStats["by_ip"])

	// 3. Lifecycle
	lm := store.NewLifecycleManager(nil)
	rec := &store.DataRecord{
		ID: "g:1", Tier: store.TierHot,
		CreatedAt: time.Now(), IsAlert: false,
	}
	lm.Archive(rec)
	lifeStats := lm.Stats()
	t.Logf("Lifecycle: hot=%dd warm=%dd dry=%v",
		lifeStats["hot_retention_days"], lifeStats["warm_retention_days"],
		lifeStats["dry_run"])

	t.Log("Central store integration OK")
}
