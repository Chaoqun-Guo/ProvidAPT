// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package server implements scalable central server infrastructure for
// ProvidAPT v2.2, featuring load distribution, priority queuing, and
// self-healing backpressure.
package server

import (
	"fmt"
	"hash/fnv"
	"log"
	"sort"
	"sync"
)

// ═══════════════════════════════════════════════════════════════
// Consistent hash router — ensures host→collector affinity
// ═══════════════════════════════════════════════════════════════

// ConsistentHashRouter maps host IDs to collector instances using
// consistent hashing, ensuring events from the same host always
// go to the same collector (maintaining temporal ordering).
type ConsistentHashRouter struct {
	mu         sync.RWMutex
	collectors []string // active collector IDs
	replicas   int      // virtual nodes per collector (for distribution)
}

// NewConsistentHashRouter creates a router with the given collectors.
func NewConsistentHashRouter(collectors []string, replicas int) *ConsistentHashRouter {
	if replicas <= 0 {
		replicas = 100
	}
	return &ConsistentHashRouter{
		collectors: collectors,
		replicas:   replicas,
	}
}

// Route returns the collector responsible for a given hostID.
func (chr *ConsistentHashRouter) Route(hostID string) string {
	chr.mu.RLock()
	defer chr.mu.RUnlock()

	if len(chr.collectors) == 0 {
		return ""
	}
	if len(chr.collectors) == 1 {
		return chr.collectors[0]
	}

	// Hashing ring approach: find the nearest collector
	hash := hashString(hostID)
	bestIdx := 0
	bestDist := uint64(0)

	for i, c := range chr.collectors {
		cHash := hashString(fmt.Sprintf("%s-%d", c, 0))
		dist := hashDistance(hash, cHash)
		if i == 0 || dist < bestDist {
			bestDist = dist
			bestIdx = i
		}
	}

	return chr.collectors[bestIdx]
}

// AddCollector adds a collector to the ring.
func (chr *ConsistentHashRouter) AddCollector(id string) {
	chr.mu.Lock()
	defer chr.mu.Unlock()
	chr.collectors = append(chr.collectors, id)
	sort.Strings(chr.collectors)
	log.Printf("[router] added collector: %s (total=%d)", id, len(chr.collectors))
}

// RemoveCollector removes a collector from the ring.
func (chr *ConsistentHashRouter) RemoveCollector(id string) {
	chr.mu.Lock()
	defer chr.mu.Unlock()
	var filtered []string
	for _, c := range chr.collectors {
		if c != id {
			filtered = append(filtered, c)
		}
	}
	chr.collectors = filtered
	log.Printf("[router] removed collector: %s (total=%d)", id, len(chr.collectors))
}

// Collectors returns the list of active collectors.
func (chr *ConsistentHashRouter) Collectors() []string {
	chr.mu.RLock()
	defer chr.mu.RUnlock()
	out := make([]string, len(chr.collectors))
	copy(out, chr.collectors)
	return out
}

// Stats returns router statistics.
func (chr *ConsistentHashRouter) Stats() map[string]interface{} {
	return map[string]interface{}{
		"collectors": len(chr.collectors),
		"replicas":   chr.replicas,
	}
}

// ─── Collector instance ─────────────────────────────────────

// Collector processes events for a subset of hosts.
type Collector struct {
	ID     string
	hosts  map[string]bool // assigned host IDs
	mu     sync.Mutex
	processed int64
}

// NewCollector creates a collector instance.
func NewCollector(id string) *Collector {
	return &Collector{
		ID:    id,
		hosts: make(map[string]bool),
	}
}

// AssignHost assigns a host to this collector.
func (c *Collector) AssignHost(hostID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hosts[hostID] = true
}

// Process simulates event processing.
func (c *Collector) Process(hostID string) {
	c.mu.Lock()
	c.processed++
	c.mu.Unlock()
}

// Stats returns collector statistics.
func (c *Collector) Stats() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]interface{}{
		"id":         c.ID,
		"hosts":      len(c.hosts),
		"processed":  c.processed,
	}
}

// ─── Helpers ────────────────────────────────────────────────

func hashString(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

func hashDistance(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
