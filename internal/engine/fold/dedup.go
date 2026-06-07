// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package fold

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Redundancy filter
// ═══════════════════════════════════════════════════════════════

// RedundancyFilter caches recent results of high-frequency syscalls
// (getdents64, access, stat) and suppresses repeated identical results.
//
// In production, this logic runs in eBPF using a BPF_MAP_TYPE_HASH.
// The userspace component manages configuration and monitors stats.
type RedundancyFilter struct {
	mu      sync.Mutex
	cache   map[string]*CacheEntry
	ttl     time.Duration // how long to cache results
	suppr   int64         // suppressed events count
	passed  int64         // passed events count
}

// CacheEntry stores a cached syscall result.
type CacheEntry struct {
	Result   int         `json:"result"`   // return value (0=success, -1=error)
	CachedAt time.Time   `json:"cached_at"`
	Count    int         `json:"count"`    // how many times this was repeated
}

// NewRedundancyFilter creates a redundancy filter.
func NewRedundancyFilter(window time.Duration) *RedundancyFilter {
	if window <= 0 {
		window = 100 * time.Millisecond // default: 100ms cache window
	}
	return &RedundancyFilter{
		cache: make(map[string]*CacheEntry),
		ttl:   window,
	}
}

// cacheKey builds a key for the redundancy cache.
func cacheKey(pid uint32, syscallID int32, path string) string {
	return fmt.Sprintf("%d:%d:%s", pid, syscallID, path)
}

// Check allows an event through if it's not a redundant repeat.
// Returns true if the event should be passed through.
// Returns false if the event should be suppressed.
func (rf *RedundancyFilter) Check(pid uint32, syscallID int32, path string, result int) bool {
	key := cacheKey(pid, syscallID, path)
	now := time.Now()

	rf.mu.Lock()
	defer rf.mu.Unlock()

	entry, exists := rf.cache[key]
	if !exists || now.Sub(entry.CachedAt) > rf.ttl {
		// First occurrence or TTL expired — allow and cache
		rf.cache[key] = &CacheEntry{
			Result:   result,
			CachedAt: now,
			Count:    1,
		}
		rf.passed++
		return true
	}

	// Check if result is the same
	if entry.Result == result {
		entry.Count++
		entry.CachedAt = now
		rf.suppr++
		log.Printf("[fold] DEDUP suppressed PID %d syscall=%d path=%s (count=%d)",
			pid, syscallID, path, entry.Count)
		return false
	}

	// Different result — update and allow
	entry.Result = result
	entry.CachedAt = now
	entry.Count = 1
	rf.passed++
	return true
}

// Stats returns filter statistics.
func (rf *RedundancyFilter) Stats() map[string]interface{} {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	total := rf.passed + rf.suppr
	efficiency := 0.0
	if total > 0 {
		efficiency = float64(rf.suppr) / float64(total) * 100.0
	}
	return map[string]interface{}{
		"cache_size":  len(rf.cache),
		"passed":      rf.passed,
		"suppressed":  rf.suppr,
		"efficiency":  fmt.Sprintf("%.1f%%", efficiency),
		"ttl":         rf.ttl.String(),
	}
}
