// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package opt

import (
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Parallel graph traversal
// ═══════════════════════════════════════════════════════════════

// TraversalResult holds the output of a parallel backward trace.
type TraversalResult struct {
	StartNode string     `json:"start_node"`
	Path      []PathStep `json:"path"`
	Duration  string     `json:"duration"`
	CacheHit  bool       `json:"cache_hit"`
}

// PathStep is a single step in a traced path.
type PathStep struct {
	NodeID   string `json:"node_id"`
	Label    string `json:"label"`
	Relation string `json:"relation"`
	Depth    int    `json:"depth"`
}

// ParallelTraverser performs concurrent backward tracing from
// multiple suspicious points, reducing query latency.
type ParallelTraverser struct {
	cache      *HotPathCache
	maxWorkers int
	traverseFn TraverseFunc
}

// TraverseFunc is the user-defined function for a single trace.
// It takes a start node ID and max depth, returns the path.
type TraverseFunc func(startNode string, maxDepth int) ([]PathStep, error)

// NewParallelTraverser creates a parallel graph traverser.
func NewParallelTraverser(cache *HotPathCache, maxWorkers int, fn TraverseFunc) *ParallelTraverser {
	if maxWorkers <= 0 {
		maxWorkers = 4
	}
	return &ParallelTraverser{
		cache:      cache,
		maxWorkers: maxWorkers,
		traverseFn: fn,
	}
}

// TraceAll runs concurrent backward traces from multiple start nodes.
// Uses a worker pool to limit concurrency.
func (pt *ParallelTraverser) TraceAll(startNodes []string, maxDepth int) []*TraversalResult {
	if len(startNodes) == 0 {
		return nil
	}

	results := make([]*TraversalResult, len(startNodes))
	var wg sync.WaitGroup
	sem := make(chan struct{}, pt.maxWorkers)

	for i, node := range startNodes {
		wg.Add(1)
		go func(idx int, startNode string) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			results[idx] = pt.traceSingle(startNode, maxDepth)
		}(i, node)
	}

	wg.Wait()
	return results
}

// traceSingle performs a single backward trace, checking cache first.
func (pt *ParallelTraverser) traceSingle(startNode string, maxDepth int) *TraversalResult {
	result := &TraversalResult{
		StartNode: startNode,
	}

	start := time.Now()

	// Check cache first
	cached := pt.cache.Get(startNode, "", "trace")
	if cached != nil {
		result.CacheHit = true
		result.Duration = time.Since(start).String()
		return result
	}

	// Execute trace function
	path, err := pt.traverseFn(startNode, maxDepth)
	if err != nil {
		log.Printf("[parallel] trace error for %s: %v", startNode, err)
		return result
	}

	result.Path = path
	result.Duration = time.Since(start).String()

	// Cache the result
	summary := ""
	if len(path) > 0 {
		summary = path[0].NodeID
	}
	pt.cache.Set(startNode, "", "trace", summary)

	return result
}

// WorkerCount returns the current worker pool size.
func (pt *ParallelTraverser) WorkerCount() int {
	return pt.maxWorkers
}

// Stats returns traverser statistics.
func (pt *ParallelTraverser) Stats() map[string]interface{} {
	return map[string]interface{}{
		"max_workers": pt.maxWorkers,
	}
}
