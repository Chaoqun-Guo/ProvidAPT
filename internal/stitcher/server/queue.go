// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"container/heap"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Priority event queue
// ═══════════════════════════════════════════════════════════════

// QueueEvent wraps an event with its priority metadata.
type QueueEvent struct {
	ID        string    `json:"id"`
	HostID    string    `json:"host_id"`
	EventType string    `json:"event_type"`
	RiskScore float64   `json:"risk_score"` // higher = more urgent
	Tainted   bool      `json:"tainted"`
	Timestamp time.Time `json:"timestamp"`
	index     int       // heap index (for heap.Interface)
}

// PriorityQueue implements heap.Interface for risk-score ordering.
type PriorityQueue []*QueueEvent

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	// Higher risk score first
	if pq[i].RiskScore != pq[j].RiskScore {
		return pq[i].RiskScore > pq[j].RiskScore
	}
	// Tainted before non-tainted
	if pq[i].Tainted != pq[j].Tainted {
		return pq[i].Tainted
	}
	// Older events first (FIFO within same priority)
	return pq[i].Timestamp.Before(pq[j].Timestamp)
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*QueueEvent)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}

// EventQueueManager manages the priority event queue.
type EventQueueManager struct {
	mu       sync.Mutex
	queue    PriorityQueue
	enqueued int64
	processed int64
}

// NewEventQueueManager creates a priority queue manager.
func NewEventQueueManager() *EventQueueManager {
	q := &EventQueueManager{}
	heap.Init(&q.queue)
	return q
}

// Enqueue adds an event to the priority queue.
func (eq *EventQueueManager) Enqueue(evt *QueueEvent) {
	eq.mu.Lock()
	heap.Push(&eq.queue, evt)
	eq.enqueued++
	eq.mu.Unlock()
}

// Dequeue removes the highest-priority event.
func (eq *EventQueueManager) Dequeue() *QueueEvent {
	eq.mu.Lock()
	defer eq.mu.Unlock()
	if eq.queue.Len() == 0 {
		return nil
	}
	evt := heap.Pop(&eq.queue).(*QueueEvent)
	eq.processed++
	return evt
}

// Peek returns the highest-priority event without removing it.
func (eq *EventQueueManager) Peek() *QueueEvent {
	eq.mu.Lock()
	defer eq.mu.Unlock()
	if eq.queue.Len() == 0 {
		return nil
	}
	return eq.queue[0]
}

// Size returns the current queue depth.
func (eq *EventQueueManager) Size() int {
	eq.mu.Lock()
	defer eq.mu.Unlock()
	return eq.queue.Len()
}

// Stats returns queue statistics.
func (eq *EventQueueManager) Stats() map[string]interface{} {
	eq.mu.Lock()
	defer eq.mu.Unlock()
	return map[string]interface{}{
		"queue_depth": eq.queue.Len(),
		"enqueued":    eq.enqueued,
		"processed":   eq.processed,
		"backlog":     eq.enqueued - eq.processed,
	}
}
