// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package opt

import (
	"container/list"
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Hot path cache — in-memory LRU for recent attack chain paths
// ═══════════════════════════════════════════════════════════════

// PathEntry is a single cached attack chain path.
type PathEntry struct {
	// Key: composite of source→target→relation
	Key string `json:"key"`

	// Source and target node IDs
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`

	// Cached data (pre-joined subgraph summary)
	SubgraphSummary string `json:"subgraph_summary,omitempty"`

	// Timestamps
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	AccessCount int       `json:"access_count"`

	// Internal LRU list element
	element *list.Element
}

// HotPathCache is an in-memory LRU cache for recently accessed
// provenance graph paths.  Reduces RocksDB reads by serving
// repeated queries from memory.
type HotPathCache struct {
	mu      sync.RWMutex
	entries map[string]*PathEntry // key → entry
	lru     *list.List            // LRU ordering
	maxSize int                   // default 10000
	ttl     time.Duration         // default 5 min
	hits    int64
	misses  int64
}

// NewHotPathCache creates an LRU hot path cache.
func NewHotPathCache(maxSize int, ttl time.Duration) *HotPathCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &HotPathCache{
		entries: make(map[string]*PathEntry),
		lru:     list.New(),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// BuildPathKey creates a cache key from source, target, relation.
func BuildPathKey(source, target, relation string) string {
	return fmt.Sprintf("%s|%s|%s", source, target, relation)
}

// Get retrieves a cached path entry.  Returns nil if not found or expired.
func (hc *HotPathCache) Get(source, target, relation string) *PathEntry {
	key := BuildPathKey(source, target, relation)

	hc.mu.RLock()
	entry, ok := hc.entries[key]
	hc.mu.RUnlock()

	if !ok {
		hc.mu.Lock()
		hc.misses++
		hc.mu.Unlock()
		return nil
	}

	// Check TTL
	if time.Since(entry.LastSeen) > hc.ttl {
		hc.Remove(key)
		hc.mu.Lock()
		hc.misses++
		hc.mu.Unlock()
		return nil
	}

	// Update LRU and stats
	hc.mu.Lock()
	hc.lru.MoveToFront(entry.element)
	entry.AccessCount++
	entry.LastSeen = time.Now()
	hc.hits++
	hc.mu.Unlock()

	return entry
}

// Set adds or updates a path entry in the cache.
func (hc *HotPathCache) Set(source, target, relation, summary string) {
	key := BuildPathKey(source, target, relation)

	hc.mu.Lock()
	defer hc.mu.Unlock()

	// Check if exists
	if existing, ok := hc.entries[key]; ok {
		hc.lru.MoveToFront(existing.element)
		existing.LastSeen = time.Now()
		existing.AccessCount++
		if summary != "" {
			existing.SubgraphSummary = summary
		}
		return
	}

	// Evict if full
	for hc.lru.Len() >= hc.maxSize {
		back := hc.lru.Back()
		if back == nil {
			break
		}
		evict := back.Value.(*PathEntry)
		delete(hc.entries, evict.Key)
		hc.lru.Remove(back)
	}

	// Insert new entry
	entry := &PathEntry{
		Key:             key,
		Source:          source,
		Target:          target,
		Relation:        relation,
		SubgraphSummary: summary,
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
		AccessCount:     1,
	}
	entry.element = hc.lru.PushFront(entry)
	hc.entries[key] = entry
}

// Remove deletes a path entry from the cache.
func (hc *HotPathCache) Remove(key string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if entry, ok := hc.entries[key]; ok {
		hc.lru.Remove(entry.element)
		delete(hc.entries, key)
	}
}

// Clear empties the entire cache.
func (hc *HotPathCache) Clear() {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.entries = make(map[string]*PathEntry)
	hc.lru = list.New()
}

// Stats returns cache performance counters.
func (hc *HotPathCache) Stats() map[string]interface{} {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	total := hc.hits + hc.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hc.hits) / float64(total) * 100.0
	}
	return map[string]interface{}{
		"size":     hc.lru.Len(),
		"max_size": hc.maxSize,
		"ttl":      hc.ttl.String(),
		"hits":     hc.hits,
		"misses":   hc.misses,
		"hit_rate": fmt.Sprintf("%.1f%%", hitRate),
	}
}

// WarmFromEdges pre-populates the cache from a batch of edges.
func (hc *HotPathCache) WarmFromEdges(edges []struct{ Source, Target, Relation string }) {
	for _, e := range edges {
		hc.Set(e.Source, e.Target, e.Relation, "")
	}
	log.Printf("[hotpath] warmed with %d edges", len(edges))
}
