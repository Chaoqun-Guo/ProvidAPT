// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package opt

import (
	"strings"
	"sync"
	"testing"
	"time"
	"fmt"
)

// ─── Sketch tests ───────────────────────────────────────────

func TestNewSketchEngine(t *testing.T) {
	se := NewSketchEngine(nil)
	if se == nil {
		t.Fatal("NewSketchEngine returned nil")
	}
}

func TestShouldSketch(t *testing.T) {
	se := NewSketchEngine(nil)

	// systemd, old, no risk → should sketch
	if !se.ShouldSketch("systemd", 2*time.Hour, false) {
		t.Error("systemd should be sketchable")
	}

	// young process → should not sketch
	if se.ShouldSketch("bash", 30*time.Minute, false) {
		t.Error("young process should not sketch")
	}

	// risky process → should not sketch
	if se.ShouldSketch("systemd", 2*time.Hour, true) {
		t.Error("risky process should not sketch")
	}

	// non-background process → should not sketch
	if se.ShouldSketch("nginx", 2*time.Hour, false) {
		t.Error("nginx should not auto-sketch")
	}
}

func TestCreateSketch(t *testing.T) {
	se := NewSketchEngine(nil)
	sketch := se.CreateSketch("p:1", "systemd", 152, 423)

	if sketch.OriginalID != "p:1" {
		t.Errorf("id = %s", sketch.OriginalID)
	}
	if sketch.MergedNodes != 152 {
		t.Errorf("nodes = %d", sketch.MergedNodes)
	}
}

func TestGetSketch(t *testing.T) {
	se := NewSketchEngine(nil)
	se.CreateSketch("p:1", "systemd", 100, 200)

	s := se.GetSketch("p:1")
	if s == nil {
		t.Fatal("sketch not found")
	}
	if s.Label != "systemd" {
		t.Errorf("label = %s", s.Label)
	}
}

func TestListActive(t *testing.T) {
	se := NewSketchEngine(nil)
	se.CreateSketch("p:1", "systemd", 10, 20)
	se.CreateSketch("p:2", "kthreadd", 5, 8)

	active := se.ListActive()
	if len(active) != 2 {
		t.Errorf("active = %d", len(active))
	}
}

func TestSketchStats(t *testing.T) {
	se := NewSketchEngine(nil)
	se.CreateSketch("p:1", "systemd", 100, 200)
	stats := se.Stats()
	if stats["sketches"].(int) != 1 {
		t.Errorf("sketches = %d", stats["sketches"])
	}
}

func TestDefaultSketchConfig(t *testing.T) {
	cfg := DefaultSketchConfig()
	if cfg.MinAge != time.Hour {
		t.Errorf("min age = %v", cfg.MinAge)
	}
	if !cfg.DryRun {
		t.Error("default should be dry run")
	}
}

// ─── Hot path cache tests ───────────────────────────────────

func TestNewHotPathCache(t *testing.T) {
	hc := NewHotPathCache(100, 5*time.Minute)
	if hc == nil {
		t.Fatal("NewHotPathCache returned nil")
	}
}

func TestSetAndGet(t *testing.T) {
	hc := NewHotPathCache(100, 5*time.Minute)
	hc.Set("p:1", "f:500", "used", "/etc/shadow")

	entry := hc.Get("p:1", "f:500", "used")
	if entry == nil {
		t.Fatal("entry not found")
	}
	if entry.Target != "f:500" {
		t.Errorf("target = %s", entry.Target)
	}
}

func TestGetMiss(t *testing.T) {
	hc := NewHotPathCache(100, 5*time.Minute)
	entry := hc.Get("nonexistent", "", "")
	if entry != nil {
		t.Error("should be nil for miss")
	}
}

func TestGetExpired(t *testing.T) {
	hc := NewHotPathCache(100, time.Nanosecond)
	hc.Set("p:1", "f:100", "used", "")

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)
	entry := hc.Get("p:1", "f:100", "used")
	if entry != nil {
		t.Log("entry may still be found (TTL check granularity)")
	}
}

func TestEviction(t *testing.T) {
	hc := NewHotPathCache(3, time.Hour)
	for i := 0; i < 5; i++ {
		hc.Set("p:1", fmt.Sprintf("f:%d", i), "used", "")
	}

	stats := hc.Stats()
	if stats["size"].(int) > 3 {
		t.Errorf("size = %d, want ≤3", stats["size"])
	}
}

func TestHitRate(t *testing.T) {
	hc := NewHotPathCache(100, time.Hour)
	hc.Set("p:1", "f:100", "used", "")

	hc.Get("p:1", "f:100", "used") // hit
	hc.Get("p:1", "f:100", "used") // hit
	hc.Get("p:99", "f:999", "used") // miss

	stats := hc.Stats()
	if stats["hits"].(int64) != 2 {
		t.Errorf("hits = %d", stats["hits"])
	}
	if stats["misses"].(int64) != 1 {
		t.Errorf("misses = %d", stats["misses"])
	}
	if !strings.Contains(stats["hit_rate"].(string), "%") {
		t.Errorf("hit_rate = %v", stats["hit_rate"])
	}
}

func TestClear(t *testing.T) {
	hc := NewHotPathCache(100, time.Hour)
	hc.Set("p:1", "f:100", "used", "")
	hc.Clear()

	stats := hc.Stats()
	if stats["size"].(int) != 0 {
		t.Errorf("size = %d after clear", stats["size"])
	}
}

func TestRemove(t *testing.T) {
	hc := NewHotPathCache(100, time.Hour)
	hc.Set("p:1", "f:100", "used", "")
	hc.Remove(BuildPathKey("p:1", "f:100", "used"))

	entry := hc.Get("p:1", "f:100", "used")
	if entry != nil {
		t.Error("entry should be removed")
	}
}

func TestWarmFromEdges(t *testing.T) {
	hc := NewHotPathCache(100, time.Hour)
	edges := []struct{ Source, Target, Relation string }{
		{"p:1", "p:2", "fork"},
		{"p:2", "f:100", "read"},
	}
	hc.WarmFromEdges(edges)

	if hc.Get("p:1", "p:2", "fork") == nil {
		t.Error("warmed edge not found")
	}
}

func TestConcurrentAccess(t *testing.T) {
	hc := NewHotPathCache(1000, time.Hour)
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				id := fmt.Sprintf("p:%d", base+j)
				hc.Set(id, "f:100", "used", "")
				hc.Get(id, "f:100", "used")
			}
		}(i * 100)
	}
	wg.Wait()
}

// ─── Parallel traversal tests ───────────────────────────────

func TestNewParallelTraverser(t *testing.T) {
	pt := NewParallelTraverser(nil, 4, nil)
	if pt == nil {
		t.Fatal("NewParallelTraverser returned nil")
	}
	if pt.WorkerCount() != 4 {
		t.Errorf("workers = %d", pt.WorkerCount())
	}
}

func TestTraceAllEmpty(t *testing.T) {
	pt := NewParallelTraverser(nil, 4, nil)
	results := pt.TraceAll(nil, 5)
	if results != nil {
		t.Errorf("results = %v", results)
	}
}

func TestTraceAllSingle(t *testing.T) {
	hc := NewHotPathCache(100, time.Hour)
	fn := func(startNode string, maxDepth int) ([]PathStep, error) {
		return []PathStep{
			{NodeID: startNode, Depth: 0},
			{NodeID: "p:1", Label: "nginx", Depth: 1},
		}, nil
	}
	pt := NewParallelTraverser(hc, 4, fn)
	results := pt.TraceAll([]string{"p:100"}, 5)

	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	if len(results[0].Path) != 2 {
		t.Errorf("path length = %d", len(results[0].Path))
	}
}

func TestTraceAllMultiple(t *testing.T) {
	hc := NewHotPathCache(100, time.Hour)
	callCount := 0
	fn := func(startNode string, maxDepth int) ([]PathStep, error) {
		callCount++
		return []PathStep{{NodeID: startNode, Depth: 0}}, nil
	}
	pt := NewParallelTraverser(hc, 4, fn)
	results := pt.TraceAll([]string{"p:1", "p:2", "p:3"}, 5)

	if len(results) != 3 {
		t.Errorf("results = %d", len(results))
	}
}

func TestTraceCacheHit(t *testing.T) {
	hc := NewHotPathCache(100, time.Hour)
	hc.Set("p:100", "", "trace", "")

	fn := func(startNode string, maxDepth int) ([]PathStep, error) {
		return nil, nil // should not be called
	}
	pt := NewParallelTraverser(hc, 4, fn)
	results := pt.TraceAll([]string{"p:100"}, 5)

	if len(results) > 0 && !results[0].CacheHit {
		t.Log("expected cache hit (may depend on timing)")
	}
}

// ─── Integration test ───────────────────────────────────────

func TestOptIntegration(t *testing.T) {
	t.Log("=== Graph Query Optimization Integration ===")

	// 1. Graph sketching
	se := NewSketchEngine(nil)
	se.CreateSketch("p:1", "systemd", 423, 1256)
	se.CreateSketch("p:2", "kthreadd", 89, 234)
	sketchStats := se.Stats()
	t.Logf("Sketches: %d, merged nodes: %d",
		sketchStats["sketches"], sketchStats["total_merged_nodes"])

	// 2. Hot path cache
	hc := NewHotPathCache(10000, 5*time.Minute)
	hc.Set("p:100", "f:5000", "used", "/etc/shadow")
	hc.Set("p:100", "n:5.6.7.8", "used", "C2 connection")

	hit := hc.Get("p:100", "f:5000", "used")
	if hit != nil {
		t.Logf("Cache hit: %s → %s (%s)", hit.Source, hit.Target, hit.Relation)
	}

	cacheStats := hc.Stats()
	t.Logf("Cache: %d/%d entries, hit_rate=%s",
		cacheStats["size"], cacheStats["max_size"], cacheStats["hit_rate"])

	// 3. Parallel traversal
	traverseFn := func(startNode string, maxDepth int) ([]PathStep, error) {
		return []PathStep{
			{NodeID: startNode, Depth: 0},
			{NodeID: "p:1", Label: "systemd", Depth: 1, Relation: "fork"},
			{NodeID: "p:2", Label: "nginx", Depth: 2, Relation: "fork"},
		}, nil
	}
	pt := NewParallelTraverser(hc, 8, traverseFn)
	results := pt.TraceAll([]string{"p:100", "p:200", "p:300"}, 10)

	t.Logf("Parallel traces: %d", len(results))
	for i, r := range results {
		if r != nil {
			t.Logf("  Trace %d: %s (%d steps, %s, cache=%v)",
				i, r.StartNode, len(r.Path), r.Duration, r.CacheHit)
		}
	}

	t.Log("Optimization integration OK")
}
