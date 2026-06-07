// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"
	"time"
)

func TestEventQueueManagerNew(t *testing.T) {
	eq := NewEventQueueManager()
	if eq == nil {
		t.Fatal("NewEventQueueManager returned nil")
	}
}

func TestEventQueueManagerEnqueueDequeue(t *testing.T) {
	eq := NewEventQueueManager()
	eq.Enqueue(&QueueEvent{ID: "evt-1", RiskScore: 1, Timestamp: time.Now()})
	eq.Enqueue(&QueueEvent{ID: "evt-2", RiskScore: 2, Timestamp: time.Now()})

	if eq.Size() != 2 {
		t.Errorf("size = %d", eq.Size())
	}

	evt := eq.Dequeue()
	if evt == nil {
		t.Fatal("expected event")
	}
}

func TestEventQueueManagerPeek(t *testing.T) {
	eq := NewEventQueueManager()
	eq.Enqueue(&QueueEvent{ID: "evt-1", RiskScore: 5, Timestamp: time.Now()})

	peeked := eq.Peek()
	if peeked == nil || peeked.ID != "evt-1" {
		t.Errorf("peek = %v", peeked)
	}
	if eq.Size() != 1 {
		t.Errorf("size after peek = %d", eq.Size())
	}
}

func TestEventQueueManagerEmptyDequeue(t *testing.T) {
	eq := NewEventQueueManager()
	evt := eq.Dequeue()
	if evt != nil {
		t.Error("expected nil from empty queue")
	}
}

func TestEventQueueManagerPriorityOrder(t *testing.T) {
	eq := NewEventQueueManager()
	eq.Enqueue(&QueueEvent{ID: "low", RiskScore: 1, Timestamp: time.Now()})
	eq.Enqueue(&QueueEvent{ID: "high", RiskScore: 10, Timestamp: time.Now()})
	eq.Enqueue(&QueueEvent{ID: "mid", RiskScore: 5, Timestamp: time.Now()})

	first := eq.Dequeue()
	if first.ID != "high" {
		t.Errorf("expected high risk first, got %s", first.ID)
	}
}

func TestEventQueueManagerStats(t *testing.T) {
	eq := NewEventQueueManager()
	eq.Enqueue(&QueueEvent{ID: "e1", RiskScore: 1, Timestamp: time.Now()})
	eq.Enqueue(&QueueEvent{ID: "e2", RiskScore: 2, Timestamp: time.Now()})

	stats := eq.Stats()
	if stats["enqueued"].(int64) != 2 {
		t.Errorf("enqueued = %d", stats["enqueued"])
	}
}

func TestConsistentHashRouterNew(t *testing.T) {
	chr := NewConsistentHashRouter([]string{"collector-1", "collector-2"}, 100)
	if chr == nil {
		t.Fatal("NewConsistentHashRouter returned nil")
	}
}

func TestConsistentHashRouterRoute(t *testing.T) {
	chr := NewConsistentHashRouter([]string{"collector-1", "collector-2"}, 100)
	dest := chr.Route("host-1")
	if dest == "" {
		t.Error("expected non-empty route")
	}
}

func TestConsistentHashRouterConsistency(t *testing.T) {
	chr := NewConsistentHashRouter([]string{"collector-1", "collector-2", "collector-3"}, 100)
	r1 := chr.Route("host-test")
	r2 := chr.Route("host-test")
	if r1 != r2 {
		t.Errorf("inconsistent routing: %s vs %s", r1, r2)
	}
}

func TestConsistentHashRouterAddRemove(t *testing.T) {
	chr := NewConsistentHashRouter([]string{"collector-1"}, 100)
	chr.AddCollector("collector-2")
	if len(chr.Collectors()) != 2 {
		t.Errorf("collectors = %d", len(chr.Collectors()))
	}

	chr.RemoveCollector("collector-1")
	if len(chr.Collectors()) != 1 {
		t.Errorf("collectors after remove = %d", len(chr.Collectors()))
	}
}

func TestConsistentHashRouterStats(t *testing.T) {
	chr := NewConsistentHashRouter([]string{"c1", "c2"}, 100)
	stats := chr.Stats()
	if stats["collectors"].(int) != 2 {
		t.Errorf("collectors = %d", stats["collectors"])
	}
}

func TestLoadControllerNew(t *testing.T) {
	eq := NewEventQueueManager()
	lc := NewLoadController(eq)
	if lc == nil {
		t.Fatal("NewLoadController returned nil")
	}
}

func TestLoadControllerTick(t *testing.T) {
	eq := NewEventQueueManager()
	lc := NewLoadController(eq)
	lc.Tick()
	level := lc.GetThrottleLevel()
	if level < 0 {
		t.Errorf("throttle level = %d", level)
	}
}

func TestLoadControllerRegisterAndHeartbeat(t *testing.T) {
	eq := NewEventQueueManager()
	lc := NewLoadController(eq)
	lc.RegisterAgent("agent-1")
	lc.Heartbeat("agent-1")
	stats := lc.Stats()
	if stats["agents"].(int) != 1 {
		t.Errorf("agents = %d", stats["registered_agents"])
	}
}

func TestCollectorNew(t *testing.T) {
	c := NewCollector("collector-1")
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
	if c.ID != "collector-1" {
		t.Errorf("id = %s", c.ID)
	}
}

func TestCollectorAssignAndProcess(t *testing.T) {
	c := NewCollector("collector-1")
	c.AssignHost("host-1")
	c.Process("host-1")
	stats := c.Stats()
	if stats["hosts"].(int) != 1 {
		t.Errorf("assigned = %d", stats["hosts"])
	}
}
