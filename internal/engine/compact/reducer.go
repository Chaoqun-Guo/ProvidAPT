// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package compact implements long-term storage optimisation for
// ProvidAPT provenance data, enabling 6-month attack backtracking
// with minimal storage overhead.
//
// It provides:
//   1. Causality-preserving reduction — merges intermediate nodes
//      (short-lived processes, temp pipes) into condensed edges.
//   2. Semantic summary generation — abstracts fine-grained I/O
//      into behaviour summaries for data > 7 days.
//   3. Cold/hot data tiering — RocksDB → Parquet → S3 lifecycle.
package compact

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Causality-preserving reduction
// ═══════════════════════════════════════════════════════════════

// ReductionConfig controls the node merging behaviour.
type ReductionConfig struct {
	// MaxIntermediateLifespan — processes shorter than this are candidates.
	MaxIntermediateLifespan time.Duration

	// MaxIntermediateDegree — nodes with degree ≤ this are candidates.
	MaxIntermediateDegree int

	// PreserveExternalIO — if false, nodes with external IO aren't merged.
	PreserveExternalIO bool

	// DryRun — if true, only report what would be merged.
	DryRun bool
}

// DefaultReductionConfig returns sensible reduction defaults.
func DefaultReductionConfig() *ReductionConfig {
	return &ReductionConfig{
		MaxIntermediateLifespan: 5 * time.Minute,
		MaxIntermediateDegree:   2,
		PreserveExternalIO:      true,
		DryRun:                  true,
	}
}

// ReductionMetrics tracks what was merged.
type ReductionMetrics struct {
	NodesExamined    int `json:"nodes_examined"`
	NodesMerged      int `json:"nodes_merged"`
	EdgesRemoved     int `json:"edges_removed"`
	EdgesCreated     int `json:"edges_created"`
	StorageSaved     int64 `json:"storage_saved_bytes"`
}

// Reducer performs causality-preserving graph reduction.
type Reducer struct {
	cfg   *ReductionConfig
	nodes map[string]*provenance.Node
	edges []*provenance.Edge
}

// NewReducer creates a graph reducer.
func NewReducer(cfg *ReductionConfig) *Reducer {
	if cfg == nil {
		cfg = DefaultReductionConfig()
	}
	return &Reducer{cfg: cfg}
}

// Reduce analyses and merges intermediate nodes in the graph.
func (r *Reducer) Reduce(graph *provenance.Graph) *ReductionMetrics {
	metrics := &ReductionMetrics{}
	nodes := graph.Nodes()
	edges := graph.Edges()

	r.nodes = make(map[string]*provenance.Node)
	for _, n := range nodes {
		r.nodes[n.ID] = n
	}
	r.edges = edges

	// Build degree index
	inDeg := make(map[string]int)
	outDeg := make(map[string]int)
	for _, e := range edges {
		outDeg[e.Source]++
		inDeg[e.Target]++
	}

	// Find intermediate nodes: low degree, short lifespan
	var intermediates []string
	for _, n := range nodes {
		metrics.NodesExamined++
		totalDeg := inDeg[n.ID] + outDeg[n.ID]

		if totalDeg > r.cfg.MaxIntermediateDegree {
			continue
		}
		if !r.isShortLived(n) {
			continue
		}
		if r.cfg.PreserveExternalIO && r.hasExternalIO(n, edges) {
			continue
		}
		if r.isSensitive(n) {
			continue
		}

		intermediates = append(intermediates, n.ID)
	}

	// Merge intermediates: for each intermediate node N,
	// replace paths A → N → B with A → B
	for _, nodeID := range intermediates {
		if !r.isMergeable(nodeID, edges) {
			continue
		}

		// Find all A→N and N→B edges
		var inEdges, outEdges []*provenance.Edge
		for _, e := range edges {
			if e.Target == nodeID {
				inEdges = append(inEdges, e)
			}
			if e.Source == nodeID {
				outEdges = append(outEdges, e)
			}
		}

		if !r.cfg.DryRun {
			r.performMerge(nodeID, inEdges, outEdges, edges, metrics)
		} else {
			metrics.NodesMerged++
			metrics.EdgesRemoved += len(inEdges) + len(outEdges)
			metrics.EdgesCreated += len(inEdges) * len(outEdges)
		}
	}

	if r.cfg.DryRun {
		log.Printf("[compact] DRY RUN: would merge %d nodes, remove %d edges, create %d edges",
			metrics.NodesMerged, metrics.EdgesRemoved, metrics.EdgesCreated)
	} else {
		log.Printf("[compact] merged %d nodes, removed %d edges, created %d edges",
			metrics.NodesMerged, metrics.EdgesRemoved, metrics.EdgesCreated)
	}

	return metrics
}

// isShortLived checks if a node has a short lifespan.
func (r *Reducer) isShortLived(n *provenance.Node) bool {
	if n == nil {
		return true
	}
	lifespan := n.LastSeen.Sub(n.FirstSeen)
	return lifespan < r.cfg.MaxIntermediateLifespan
}

// hasExternalIO checks if a node has external interactions.
func (r *Reducer) hasExternalIO(n *provenance.Node, edges []*provenance.Edge) bool {
	for _, e := range edges {
		if e.Source == n.ID || e.Target == n.ID {
			for _, oe := range edges {
				if oe.Target == e.Target && oe.Source != n.ID {
					// Another process also touches this target
					return true
				}
			}
		}
	}
	return false
}

// isSensitive checks if a node is sensitive and should be preserved.
func (r *Reducer) isSensitive(n *provenance.Node) bool {
	sensitive := []string{"shadow", "passwd", "sudo", "ssh", "cred"}
	for _, s := range sensitive {
		if strings.Contains(strings.ToLower(n.Label), s) {
			return true
		}
	}
	return false
}

// isMergeable checks if an intermediate node can be safely merged.
func (r *Reducer) isMergeable(nodeID string, edges []*provenance.Edge) bool {
	var hasIn, hasOut bool
	for _, e := range edges {
		if e.Target == nodeID {
			hasIn = true
		}
		if e.Source == nodeID {
			hasOut = true
		}
	}
	return hasIn && hasOut
}

// performMerge replaces A→N→B with A→B.
func (r *Reducer) performMerge(nodeID string, inEdges, outEdges []*provenance.Edge,
	allEdges []*provenance.Edge, metrics *ReductionMetrics) {

	for _, in := range inEdges {
		for _, out := range outEdges {
			// Create merged edge: in.Source → out.Target
			newEdge := &provenance.Edge{
				Source:    in.Source,
				Target:    out.Target,
				Relation:  in.Relation,
				Timestamp: out.Timestamp,
				Count:     in.Count + out.Count,
			}
			allEdges = append(allEdges, newEdge)
			metrics.EdgesCreated++
		}
		metrics.EdgesRemoved++
	}
	metrics.EdgesRemoved += len(outEdges)
	metrics.NodesMerged++

	// Estimate storage saved
	metrics.StorageSaved += 332 + int64(len(inEdges)+len(outEdges))*250
}

// Summary returns a human-readable reduction summary.
func (rm *ReductionMetrics) Summary() string {
	return fmt.Sprintf("Reduction: %d/%d nodes merged, %d edges → %d edges (saved %.1f KB)",
		rm.NodesMerged, rm.NodesExamined, rm.EdgesRemoved, rm.EdgesCreated,
		float64(rm.StorageSaved)/1024)
}
