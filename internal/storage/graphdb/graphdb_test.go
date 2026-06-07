// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package graphdb

import (
	"testing"
	"time"
)

// ─── MemGraphDB tests ─────────────────────────────────

func TestNewMemGraphDB(t *testing.T) {
	db := NewMemGraphDB()
	if db == nil {
		t.Fatal("NewMemGraphDB returned nil")
	}
	if len(db.nodes) != 0 {
		t.Errorf("nodes = %d", len(db.nodes))
	}
}

func TestCreateNode(t *testing.T) {
	db := NewMemGraphDB()
	id, err := db.CreateNode("process", "p:100", "bash", map[string]interface{}{
		"host_id": "host1",
		"pid":     uint32(100),
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if id != "p:100" {
		t.Errorf("id = %s", id)
	}
	if len(db.nodes) != 1 {
		t.Errorf("nodes = %d", len(db.nodes))
	}
}

func TestCreateEdge(t *testing.T) {
	db := NewMemGraphDB()
	db.CreateNode("process", "p:100", "bash", nil)
	db.CreateNode("file", "f:500", "/etc/shadow", nil)
	eid, err := db.CreateEdge("p:100", "f:500", "used", nil)
	if err != nil {
		t.Fatalf("CreateEdge: %v", err)
	}
	if eid != "e:p:100-f:500-used" {
		t.Errorf("edge id = %s", eid)
	}
}

func TestQueryNodes(t *testing.T) {
	db := NewMemGraphDB()
	db.CreateNode("process", "p:100", "bash", map[string]interface{}{"host_id": "host1"})
	db.CreateNode("process", "p:200", "sshd", map[string]interface{}{"host_id": "host2"})
	db.CreateNode("file", "f:500", "/etc/shadow", map[string]interface{}{"host_id": "host1"})

	// Query all process nodes
	results, err := db.QueryNodes("process", nil)
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("process nodes = %d, want 2", len(results))
	}

	// Query all nodes
	results, err = db.QueryNodes("", nil)
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("all nodes = %d, want 3", len(results))
	}
}

func TestQueryNodesWithProps(t *testing.T) {
	db := NewMemGraphDB()
	db.CreateNode("process", "p:100", "bash", map[string]interface{}{"host_id": "host1"})
	db.CreateNode("process", "p:200", "bash", map[string]interface{}{"host_id": "host2"})

	results, err := db.QueryNodes("process", map[string]interface{}{"host_id": "host1"})
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("host1 nodes = %d, want 1", len(results))
	}
}

func TestQueryPaths(t *testing.T) {
	db := NewMemGraphDB()
	db.CreateNode("process", "p:100", "bash", nil)
	db.CreateNode("process", "p:200", "sshd", nil)
	db.CreateNode("process", "p:300", "curl", nil)
	db.CreateEdge("p:100", "p:200", "wasInformedBy", nil)
	db.CreateEdge("p:200", "p:300", "wasInformedBy", nil)

	paths, err := db.QueryPaths("p:100", "p:300", 5)
	if err != nil {
		t.Fatalf("QueryPaths: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("expected path between p:100 and p:300")
	}
	path := paths[0]["path"].([]string)
	if len(path) < 3 {
		t.Errorf("path length = %d", len(path))
	}
}

func TestQueryPathsNoPath(t *testing.T) {
	db := NewMemGraphDB()
	db.CreateNode("process", "p:100", "bash", nil)
	db.CreateNode("process", "p:999", "isolated", nil)

	paths, err := db.QueryPaths("p:100", "p:999", 5)
	if err != nil {
		t.Fatalf("QueryPaths: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("expected no path, got %d", len(paths))
	}
}

func TestClose(t *testing.T) {
	db := NewMemGraphDB()
	err := db.Close()
	if err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestStats(t *testing.T) {
	db := NewMemGraphDB()
	db.CreateNode("process", "p:100", "bash", nil)
	db.CreateEdge("p:100", "p:200", "used", nil)
	stats := db.Stats()
	if stats["nodes"].(int) != 1 {
		t.Errorf("nodes = %d", stats["nodes"])
	}
	if stats["edges"].(int) != 1 {
		t.Errorf("edges = %d", stats["edges"])
	}
}

func TestMatchProps(t *testing.T) {
	nodeProps := map[string]interface{}{
		"host_id": "host1",
		"pid":     uint32(100),
	}
	if !matchProps(nodeProps, map[string]interface{}{"host_id": "host1"}) {
		t.Error("should match host_id")
	}
	if matchProps(nodeProps, map[string]interface{}{"host_id": "host2"}) {
		t.Error("should not match different host_id")
	}
	if matchProps(nodeProps, map[string]interface{}{"nonexistent": "val"}) {
		t.Error("should not match missing key")
	}
}

// ─── InsertSubgraph tests ─────────────────────────────

func TestInsertSubgraph(t *testing.T) {
	db := NewMemGraphDB()
	nodes := []GlobalNode{
		{ID: "p:100", Type: "process", Label: "bash", HostID: "host1", AgentID: "agent1"},
		{ID: "f:500", Type: "file", Label: "/etc/shadow", HostID: "host1"},
	}
	edges := []GlobalEdge{
		{Source: "p:100", Target: "f:500", Relation: "used", HostID: "host1"},
	}
	err := InsertSubgraph(db, nodes, edges)
	if err != nil {
		t.Fatalf("InsertSubgraph: %v", err)
	}

	results, _ := db.QueryNodes("", nil)
	if len(results) != 2 {
		t.Errorf("nodes after insert = %d", len(results))
	}
}

// ─── GlobalIndex tests ────────────────────────────────

func TestNewGlobalIndex(t *testing.T) {
	gi := NewGlobalIndex()
	if gi == nil {
		t.Fatal("NewGlobalIndex returned nil")
	}
}

func TestIndexNode(t *testing.T) {
	gi := NewGlobalIndex()
	node := &GlobalNode{
		ID: "p:100", Type: "process", Label: "bash",
		HostID: "host1", AgentID: "agent1",
		Props: map[string]interface{}{
			"identity": "root",
			"ip":       "10.0.0.1",
		},
	}
	gi.IndexNode(node)

	byHost := gi.QueryByHostID("host1")
	if len(byHost) != 1 {
		t.Errorf("byHost = %d", len(byHost))
	}

	byIP := gi.QueryByIP("10.0.0.1")
	if len(byIP) != 1 {
		t.Errorf("byIP = %d", len(byIP))
	}

	byIdent := gi.QueryByIdentity("root")
	if len(byIdent) != 1 {
		t.Errorf("byIdent = %d", len(byIdent))
	}
}

func TestGlobalBacktrack(t *testing.T) {
	gi := NewGlobalIndex()
	node := &GlobalNode{
		ID: "p:100", Type: "process", Label: "bash", HostID: "host1",
	}
	gi.IndexNode(node)

	path := gi.GlobalBacktrack("p:100")
	if len(path) != 1 || path[0] != "host1" {
		t.Errorf("backtrack = %v", path)
	}

	path = gi.GlobalBacktrack("nonexistent")
	if path != nil {
		t.Errorf("expected nil for nonexistent: %v", path)
	}
}

func TestIndexStats(t *testing.T) {
	gi := NewGlobalIndex()
	stats := gi.Stats()
	if stats["by_host_id"].(int) != 0 {
		t.Errorf("by_host_id = %d", stats["by_host_id"])
	}
}

func TestExtractIPs(t *testing.T) {
	tests := []struct {
		node *GlobalNode
		want int
	}{
		{&GlobalNode{Label: "10.0.0.1", Props: map[string]interface{}{}}, 1},
		{&GlobalNode{Label: "bash", Props: map[string]interface{}{"ip": "10.0.0.2"}}, 1},
		{&GlobalNode{Label: "/etc/shadow", Props: map[string]interface{}{}}, 0},
		{&GlobalNode{Label: "10.0.0.1", Props: map[string]interface{}{"src_ip": "10.0.0.2"}}, 2},
	}
	for _, tt := range tests {
		ips := extractIPs(tt.node)
		if len(ips) != tt.want {
			t.Errorf("extractIPs(%q) = %d, want %d", tt.node.Label, len(ips), tt.want)
		}
	}
}

// ─── Lifecycle tests ──────────────────────────────────

func TestDefaultLifecycleConfig(t *testing.T) {
	cfg := DefaultLifecycleConfig()
	if cfg.HotRetention != 7 {
		t.Errorf("HotRetention = %d", cfg.HotRetention)
	}
	if cfg.WarmRetention != 30 {
		t.Errorf("WarmRetention = %d", cfg.WarmRetention)
	}
	if !cfg.EnableAutoArchival {
		t.Error("EnableAutoArchival should be true")
	}
	if !cfg.DryRun {
		t.Error("DryRun should be true by default")
	}
}

func TestNewLifecycleManager(t *testing.T) {
	lm := NewLifecycleManager(nil)
	if lm == nil {
		t.Fatal("NewLifecycleManager returned nil")
	}
}

func TestClassifyHot(t *testing.T) {
	lm := NewLifecycleManager(nil)
	tier := lm.Classify(time.Now(), false)
	if tier != TierHot {
		t.Errorf("tier = %d, want TierHot(0)", tier)
	}
}

func TestClassifyWarm(t *testing.T) {
	lm := NewLifecycleManager(nil)
	tier := lm.Classify(time.Now().Add(-14*24*time.Hour), false)
	if tier != TierWarm {
		t.Errorf("tier = %d, want TierWarm(1)", tier)
	}
}

func TestClassifyColdNonAlert(t *testing.T) {
	lm := NewLifecycleManager(nil)
	tier := lm.Classify(time.Now().Add(-60*24*time.Hour), false)
	if tier != TierCold {
		t.Errorf("tier = %d, want TierCold(2)", tier)
	}
}

func TestShouldPrune(t *testing.T) {
	lm := NewLifecycleManager(nil)
	// Recent data should not be pruned
	if lm.ShouldPrune(time.Now(), false) {
		t.Error("recent data should not be pruned")
	}
	// Old alert data should not be pruned
	if lm.ShouldPrune(time.Now().Add(-60*24*time.Hour), true) {
		t.Error("old alert data should not be pruned")
	}
	// Old non-alert data should be pruned
	if !lm.ShouldPrune(time.Now().Add(-60*24*time.Hour), false) {
		t.Error("old non-alert data should be pruned")
	}
}

func TestArchiveNoTransition(t *testing.T) {
	lm := NewLifecycleManager(DefaultLifecycleConfig())
	rec := &DataRecord{ID: "test", Tier: TierHot, CreatedAt: time.Now(), IsAlert: false}
	newTier := lm.Archive(rec)
	if newTier != TierHot {
		t.Errorf("tier = %d", newTier)
	}
}

func TestArchiveHotToWarm(t *testing.T) {
	cfg := DefaultLifecycleConfig()
	cfg.DryRun = false
	lm := NewLifecycleManager(cfg)
	rec := &DataRecord{ID: "test", Tier: TierHot, CreatedAt: time.Now().Add(-14 * 24 * time.Hour), IsAlert: false}
	newTier := lm.Archive(rec)
	if newTier != TierWarm {
		t.Errorf("tier = %d, want TierWarm", newTier)
	}
	if rec.Tier != TierWarm {
		t.Error("record tier not updated")
	}
}

func TestArchiveWarmToCold(t *testing.T) {
	cfg := DefaultLifecycleConfig()
	cfg.DryRun = false
	lm := NewLifecycleManager(cfg)
	rec := &DataRecord{ID: "test", Tier: TierWarm, CreatedAt: time.Now().Add(-60 * 24 * time.Hour), IsAlert: false}
	newTier := lm.Archive(rec)
	if newTier != TierCold {
		t.Errorf("tier = %d, want TierCold", newTier)
	}
}

func TestTick(t *testing.T) {
	lm := NewLifecycleManager(nil)
	lm.Tick() // should not panic
}

func TestLifecycleStats(t *testing.T) {
	lm := NewLifecycleManager(nil)
	stats := lm.Stats()
	if stats["hot_retention_days"].(int) != 7 {
		t.Errorf("hot_retention = %d", stats["hot_retention_days"])
	}
	if stats["dry_run"].(bool) != true {
		t.Error("dry_run should be true")
	}
}

func TestDataTierValues(t *testing.T) {
	if TierHot != 0 {
		t.Errorf("TierHot = %d", TierHot)
	}
	if TierWarm != 1 {
		t.Errorf("TierWarm = %d", TierWarm)
	}
	if TierCold != 2 {
		t.Errorf("TierCold = %d", TierCold)
	}
}
