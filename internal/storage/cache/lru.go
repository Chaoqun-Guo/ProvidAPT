// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package cache provides an LRU (Least Recently Used) cache for
// provenance graph nodes.  Hot/active nodes stay in memory; cold nodes
// are evicted to a persistent store.
package cache

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

// ─── EvictCallback ──────────────────────────────────────────

// EvictCallback is called when a node is evicted from the cache.
// The implementation should persist the node to RocksDB.
type EvictCallback func(id string) error

// ─── Cache ──────────────────────────────────────────────────

// Cache is a fixed-size LRU cache for provenance nodes.
// It is safe for concurrent use.
type Cache struct {
	mu       sync.RWMutex
	maxSize  int
	evictFn  EvictCallback
	items    map[string]*list.Element
	order    *list.List
	hits     int64
	misses   int64
}

type entry struct {
	key       string
	nodeID    string
	lastTouch time.Time
}

// New creates an LRU cache.
//
//   maxSize  — maximum number of nodes kept in memory (0 = 4096)
//   evictFn  — called synchronously during eviction; persists the node
func New(maxSize int, evictFn EvictCallback) (*Cache, error) {
	if maxSize <= 0 {
		maxSize = 4096
	}
	if evictFn == nil {
		return nil, fmt.Errorf("cache: evictFn must not be nil")
	}
	return &Cache{
		maxSize: maxSize,
		evictFn: evictFn,
		items:   make(map[string]*list.Element),
		order:   list.New(),
	}, nil
}

// ── Core operations ────────────────────────────────────────

// Contains returns true if the node is in the cache.
func (c *Cache) Contains(id string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.items[id]
	return ok
}

// Get retrieves a node, marking it as recently used.
// Returns false if the node is not present.
func (c *Cache) Get(id string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[id]; ok {
		c.order.MoveToFront(el)
		el.Value.(*entry).lastTouch = time.Now()
		c.hits++
		return true, nil
	}
	c.misses++
	return false, nil
}

// Add inserts or refreshes a node in the cache.
// If the cache is full, the least recently used node is evicted via
// the EvictCallback before adding the new one.
func (c *Cache) Add(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Already present — move to front
	if el, ok := c.items[id]; ok {
		c.order.MoveToFront(el)
		el.Value.(*entry).lastTouch = time.Now()
		return nil
	}

	// Evict if full
	for c.order.Len() >= c.maxSize {
		if err := c.evictLocked(); err != nil {
			return fmt.Errorf("cache evict: %w", err)
		}
	}

	// Insert at front
	c.items[id] = c.order.PushFront(&entry{
		key:       id,
		nodeID:    id,
		lastTouch: time.Now(),
	})
	return nil
}

// Remove deletes a node from the cache without calling the evict callback.
func (c *Cache) Remove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[id]; ok {
		c.order.Remove(el)
		delete(c.items, id)
	}
}

// ── Eviction ───────────────────────────────────────────────

// evictLocked removes the least recently used node.  Caller must hold c.mu.
func (c *Cache) evictLocked() error {
	el := c.order.Back()
	if el == nil {
		return nil
	}
	ent := el.Value.(*entry)

	// Persist before removing
	if err := c.evictFn(ent.nodeID); err != nil {
		return err
	}

	c.order.Remove(el)
	delete(c.items, ent.key)
	return nil
}

// EvictColdSync forces eviction of a batch of cold entries.
// Used by the memory pressure handler to free memory proactively.
func (c *Cache) EvictColdSync(count int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	evicted := 0
	for i := 0; i < count && c.order.Len() > 0; i++ {
		if err := c.evictLocked(); err != nil {
			return evicted, err
		}
		evicted++
	}
	return evicted, nil
}

// ── Stats ───────────────────────────────────────────────────

// Stats returns cache performance counters.
func (c *Cache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	total := c.hits + c.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(c.hits) / float64(total) * 100.0
	}
	return map[string]interface{}{
		"size":     c.order.Len(),
		"max_size": c.maxSize,
		"hits":     c.hits,
		"misses":   c.misses,
		"hit_rate": fmt.Sprintf("%.1f%%", hitRate),
	}
}

// Len returns the current number of cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.order.Len()
}
