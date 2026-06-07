// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package opt provides graph query performance optimizations for
// ProvidAPT v2.1: graph sketching, hot-path caching, parallel traversal.
package opt

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Graph sketching — background summary node
// ═══════════════════════════════════════════════════════════════

// SketchNode is a compressed representation of a no-risk subgraph.
type SketchNode struct {
	OriginalID    string   `json:"original_id"`    // e.g., "p:1" for systemd
	Label         string   `json:"label"`           // "systemd"
	MergedNodes   int      `json:"merged_nodes"`    // how many nodes collapsed
	MergedEdges   int      `json:"merged_edges"`    // how many edges collapsed
	LastActivity  time.Time `json:"last_activity"`
	KeyStats      string   `json:"key_stats"`       // e.g., "forks=42, reads=156"
}

// SketchConfig controls which processes get sketched.
type SketchConfig struct {
	// MinAge — process must be older than this to qualify (default 1h).
	MinAge time.Duration

	// NoRiskLabels — labels that indicate no risk.
	NoRiskLabels []string

	// BackgroundPrefixes — process comm prefixes to auto-sketch.
	BackgroundPrefixes []string

	// EnableSketching — master switch.
	EnableSketching bool

	// DryRun — if true, log what would be sketched but don't merge.
	DryRun bool
}

// DefaultSketchConfig returns sensible defaults.
func DefaultSketchConfig() *SketchConfig {
	return &SketchConfig{
		MinAge:     1 * time.Hour,
		NoRiskLabels: []string{"CLEAN", "system", "kernel"},
		BackgroundPrefixes: []string{
			"systemd", "kernel", "kworker", "kthread",
			"watchdog", "irq", "rcu",
		},
		EnableSketching: true,
		DryRun:          true,
	}
}

// SketchEngine manages graph sketching.
type SketchEngine struct {
	cfg     *SketchConfig
	mu      sync.Mutex
	sketches map[string]*SketchNode // originalID → sketch
}

// NewSketchEngine creates a graph sketching engine.
func NewSketchEngine(cfg *SketchConfig) *SketchEngine {
	if cfg == nil {
		cfg = DefaultSketchConfig()
	}
	return &SketchEngine{
		cfg:      cfg,
		sketches: make(map[string]*SketchNode),
	}
}

// ShouldSketch checks if a process qualifies for background sketching.
func (se *SketchEngine) ShouldSketch(comm string, age time.Duration, hasRisk bool) bool {
	if !se.cfg.EnableSketching {
		return false
	}
	if hasRisk {
		return false
	}
	if age < se.cfg.MinAge {
		return false
	}
	for _, prefix := range se.cfg.BackgroundPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return true
		}
	}
	return false
}

// CreateSketch creates or updates a sketch node for a process.
func (se *SketchEngine) CreateSketch(originalID, label string, mergedNodes, mergedEdges int) *SketchNode {
	sketch := &SketchNode{
		OriginalID:   originalID,
		Label:        label,
		MergedNodes:  mergedNodes,
		MergedEdges:  mergedEdges,
		LastActivity: time.Now(),
		KeyStats:     fmt.Sprintf("nodes=%d, edges=%d", mergedNodes, mergedEdges),
	}

	se.mu.Lock()
	se.sketches[originalID] = sketch
	se.mu.Unlock()

	if se.cfg.DryRun {
		log.Printf("[sketch] DRY: merged %s (%d nodes, %d edges)", label, mergedNodes, mergedEdges)
	} else {
		log.Printf("[sketch] merged %s into sketch node (%d nodes, %d edges)", label, mergedNodes, mergedEdges)
	}

	return sketch
}

// GetSketch returns the sketch node for a process.
func (se *SketchEngine) GetSketch(originalID string) *SketchNode {
	se.mu.Lock()
	defer se.mu.Unlock()
	return se.sketches[originalID]
}

// ListActive returns all active sketch nodes.
func (se *SketchEngine) ListActive() []*SketchNode {
	se.mu.Lock()
	defer se.mu.Unlock()
	out := make([]*SketchNode, 0, len(se.sketches))
	for _, s := range se.sketches {
		out = append(out, s)
	}
	return out
}

// Stats returns sketch engine statistics.
func (se *SketchEngine) Stats() map[string]interface{} {
	se.mu.Lock()
	defer se.mu.Unlock()
	return map[string]interface{}{
		"sketches":        len(se.sketches),
		"total_merged_nodes": func() int {
			n := 0
			for _, s := range se.sketches {
				n += s.MergedNodes
			}
			return n
		}(),
		"dry_run": se.cfg.DryRun,
	}
}
