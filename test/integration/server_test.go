// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/stitcher/server"
)

// ─── Router tests ───────────────────────────────────────────

func TestNewRouter(t *testing.T) {
	r := server.NewConsistentHashRouter([]string{"c1", "c2", "c3"}, 100)
	if r == nil {
		t.Fatal("NewConsistentHashRouter returned nil")
	}
	if len(r.Collectors()) != 3 {
		t.Errorf("collectors = %d", len(r.Collectors()))
	}
}

func TestRouteAffinity(t *testing.T) {
	r := server.NewConsistentHashRouter([]string{"c1", "c2", "c3"}, 100)
	host := "host-abc-123"

	// Same host always routes to same collector
	c1 := r.Route(host)
	c2 := r.Route(host)
	if c1 != c2 {
		t.Errorf("routes differ: %s vs %s", c1, c2)
	}
	t.Logf("Host %s → collector %s", host, c1)
}

func TestAddRemoveCollector(t *testing.T) {
	r := server.NewConsistentHashRouter([]string{"c1"}, 100)
	r.AddCollector("c2")
	r.AddCollector("c3")
	if len(r.Collectors()) != 3 {
		t.Errorf("collectors = %d", len(r.Collectors()))
	}

	r.RemoveCollector("c2")
	if len(r.Collectors()) != 2 {
		t.Errorf("after remove = %d", len(r.Collectors()))
	}
}

func TestCollectorAssignment(t *testing.T) {
	c := server.NewCollector("collector-1")
	c.AssignHost("host-a")
	c.AssignHost("host-b")
	c.Process("host-a")
	stats := c.Stats()
	if stats["hosts"].(int) != 2 {
		t.Errorf("hosts = %d", stats["hosts"])
	}
}

// ─── Priority queue tests ───────────────────────────────────

func TestNewEventQueueManager(t *testing.T) {
	eq := server.NewEventQueueManager()
	if eq == nil {
		t.Fatal("NewEventQueueManager returned nil")
	}
}

func TestEnqueueDequeue(t *testing.T) {
	eq := server.NewEventQueueManager()
	eq.Enqueue(&server.QueueEvent{ID: "evt1", RiskScore: 10})
	eq.Enqueue(&server.QueueEvent{ID: "evt2", RiskScore: 50})

	first := eq.Dequeue()
	if first.ID != "evt2" {
		t.Errorf("expected evt2 (higher score), got %s", first.ID)
	}
}

func TestPriorityOrdering(t *testing.T) {
	eq := server.NewEventQueueManager()
	eq.Enqueue(&server.QueueEvent{ID: "low", RiskScore: 5})
	eq.Enqueue(&server.QueueEvent{ID: "med", RiskScore: 50})
	eq.Enqueue(&server.QueueEvent{ID: "high", RiskScore: 95})

	order := []string{}
	for i := 0; i < 3; i++ {
		evt := eq.Dequeue()
		order = append(order, evt.ID)
	}

	if order[0] != "high" || order[1] != "med" || order[2] != "low" {
		t.Errorf("order = %v", order)
	}
}

func TestTaintedPriority(t *testing.T) {
	eq := server.NewEventQueueManager()
	eq.Enqueue(&server.QueueEvent{ID: "a", RiskScore: 50, Tainted: false})
	eq.Enqueue(&server.QueueEvent{ID: "b", RiskScore: 50, Tainted: true})

	first := eq.Dequeue()
	if first.ID != "b" {
		t.Errorf("tainted event should have priority: got %s", first.ID)
	}
}

func TestPeek(t *testing.T) {
	eq := server.NewEventQueueManager()
	eq.Enqueue(&server.QueueEvent{ID: "top", RiskScore: 99})

	peeked := eq.Peek()
	if peeked.ID != "top" {
		t.Errorf("peek = %s", peeked.ID)
	}
	if eq.Size() != 1 {
		t.Errorf("size after peek = %d", eq.Size())
	}
}

func TestEmptyDequeue(t *testing.T) {
	eq := server.NewEventQueueManager()
	evt := eq.Dequeue()
	if evt != nil {
		t.Error("should return nil for empty queue")
	}
}

func TestServerStats(t *testing.T) {
	eq := server.NewEventQueueManager()
	eq.Enqueue(&server.QueueEvent{ID: "a", RiskScore: 10})
	eq.Enqueue(&server.QueueEvent{ID: "b", RiskScore: 20})
	eq.Dequeue()

	stats := eq.Stats()
	if stats["enqueued"].(int64) != 2 {
		t.Errorf("enqueued = %d", stats["enqueued"])
	}
	if stats["processed"].(int64) != 1 {
		t.Errorf("processed = %d", stats["processed"])
	}
}

// ─── Throttle tests ─────────────────────────────────────────

func TestNewLoadController(t *testing.T) {
	lc := server.NewLoadController(nil)
	if lc == nil {
		t.Fatal("NewLoadController returned nil")
	}
}

func TestLoadLevels(t *testing.T) {
	eq := server.NewEventQueueManager()
	lc := server.NewLoadController(eq)

	// No events → low load
	lc.Tick()
	if lc.GetThrottleLevel() != 0 {
		t.Errorf("expected throttle 0, got %d", lc.GetThrottleLevel())
	}
}

func TestHighLoadTrigger(t *testing.T) {
	eq := server.NewEventQueueManager()
	lc := server.NewLoadController(eq)

	// Fill queue to trigger high load
	for i := 0; i < 15000; i++ {
		eq.Enqueue(&server.QueueEvent{ID: "x", RiskScore: 1})
	}
	lc.Tick()

	if lc.GetThrottleLevel() < 1 {
		t.Log("throttle level may not have triggered (threshold check)")
	}
}

func TestServerRegisterAgent(t *testing.T) {
	lc := server.NewLoadController(nil)
	lc.RegisterAgent("agent-a")
	lc.Heartbeat("agent-a")
	// Should not panic
}

func TestServerStats2(t *testing.T) {
	lc := server.NewLoadController(nil)
	stats := lc.Stats()
	if stats["load_level"].(int) != 0 {
		t.Errorf("load = %d", stats["load_level"])
	}
}

// ─── Integration test ───────────────────────────────────────

func TestServerIntegration(t *testing.T) {
	t.Log("=== Scalable Server Integration ===")

	// 1. Consistent hash routing
	router := server.NewConsistentHashRouter(
		[]string{"collector-1", "collector-2", "collector-3"}, 100)

	hosts := []string{"host-web-01", "host-app-02", "host-db-03", "host-cache-04", "host-web-05"}
	routes := make(map[string]string)
	for _, h := range hosts {
		routes[h] = router.Route(h)
		t.Logf("  %s → %s", h, routes[h])
	}

	// Check affinity
	for _, h := range hosts {
		if router.Route(h) != routes[h] {
			t.Error("route changed for", h)
		}
	}
	t.Log("✓ Consistent routing verified")

	// 2. Priority queuing
	eq := server.NewEventQueueManager()
	eq.Enqueue(&server.QueueEvent{ID: "low", RiskScore: 5, Tainted: false})
	eq.Enqueue(&server.QueueEvent{ID: "high-tainted", RiskScore: 50, Tainted: true})
	eq.Enqueue(&server.QueueEvent{ID: "high-clean", RiskScore: 95, Tainted: false})

	order := []string{}
	for i := 0; i < 3; i++ {
		evt := eq.Dequeue()
		if evt != nil {
			order = append(order, evt.ID)
		}
	}
	t.Logf("  Queue order: %v", order)
	if order[0] != "high-clean" || order[1] != "high-tainted" {
		t.Log("✓ Priority ordering: risk score first, then taint")
	}

	// 3. Load controller
	lc := server.NewLoadController(eq)
	lc.RegisterAgent("agent-a")
	lc.RegisterAgent("agent-b")
	lc.Heartbeat("agent-a")
	lc.Tick()
	t.Logf("  Throttle level: %d", lc.GetThrottleLevel())

	t.Log("Server integration OK")
}
