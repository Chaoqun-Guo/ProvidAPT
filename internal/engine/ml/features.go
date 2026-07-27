// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package ml provides machine learning-based anomaly detection for
// provenance graphs.  It extracts structural features from subgraphs
// and uses an Isolation Forest / statistical model to identify
// unusual patterns that may indicate unknown APT attacks.
package ml

import (
	"math"
	"sort"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// Feature vector.
// FeatureIndex names the position of each feature in the vector.
type FeatureIndex int

const (
	FiNodeCount FeatureIndex = iota
	FiEdgeCount
	FiGraphDensity
	FiAvgDegree
	FiMaxDegree
	FiStddevDegree
	FiProcessRatio
	FiFileRatio
	FiNetworkRatio
	FiUsedEdgeRatio
	FiGeneratedByRatio
	FiInformedByRatio
	FiAvgPathLength
	FiMaxPathLength
	FiInteractionEntropy
	NumFeatures // total feature count
)

// FeatureNames returns human-readable names for each feature.
func FeatureNames() [NumFeatures]string {
	return [NumFeatures]string{
		"node_count",
		"edge_count",
		"graph_density",
		"avg_degree",
		"max_degree",
		"stddev_degree",
		"process_ratio",
		"file_ratio",
		"network_ratio",
		"used_edge_ratio",
		"generated_by_ratio",
		"informed_by_ratio",
		"avg_path_length",
		"max_path_length",
		"interaction_entropy",
	}
}

// FeatureVector is a fixed-length vector of numerical features
// extracted from a provenance subgraph.
type FeatureVector [NumFeatures]float64

// ExtractFeatures computes a feature vector from a set of nodes and
// edges (typically a subgraph around a suspicious root).
func ExtractFeatures(nodes []*provenance.Node, edges []*provenance.Edge) FeatureVector {
	var fv FeatureVector

	if len(nodes) == 0 {
		return fv
	}

	// Size features
	fv[FiNodeCount] = float64(len(nodes))
	fv[FiEdgeCount] = float64(len(edges))

	// Density
	maxPossible := float64(len(nodes) * (len(nodes) - 1))
	if maxPossible > 0 {
		fv[FiGraphDensity] = float64(len(edges)) / maxPossible
	}

	// Degree computation
	inDeg := make(map[string]int)
	outDeg := make(map[string]int)
	deg := make([]float64, 0, len(nodes))

	for _, e := range edges {
		inDeg[e.Target]++
		outDeg[e.Source]++
	}

	for _, n := range nodes {
		d := float64(inDeg[n.ID] + outDeg[n.ID])
		deg = append(deg, d)
	}
	fv[FiAvgDegree] = avg(deg)
	fv[FiMaxDegree] = maxFloat(deg)
	fv[FiStddevDegree] = stddev(deg)

	// Type ratios
	var procCount, fileCount, netCount float64
	for _, n := range nodes {
		switch n.Subtype {
		case "process":
			procCount++
		case "file":
			fileCount++
		case "network":
			netCount++
		}
	}
	total := float64(len(nodes))
	fv[FiProcessRatio] = procCount / total
	fv[FiFileRatio] = fileCount / total
	fv[FiNetworkRatio] = netCount / total

	// Edge type ratios
	var usedCount, genCount, infCount float64
	for _, e := range edges {
		switch e.Relation {
		case provenance.ProvUsed:
			usedCount++
		case provenance.ProvWasGeneratedBy:
			genCount++
		case provenance.ProvWasInformedBy:
			infCount++
		}
	}
	etotal := float64(len(edges))
	if etotal > 0 {
		fv[FiUsedEdgeRatio] = usedCount / etotal
		fv[FiGeneratedByRatio] = genCount / etotal
		fv[FiInformedByRatio] = infCount / etotal
	}

	// Path features (BFS from roots)
	fv[FiAvgPathLength], fv[FiMaxPathLength] = computePathStats(nodes, edges)

	// Interaction entropy
	fv[FiInteractionEntropy] = computeEntropy(deg)

	return fv
}

// Path computation.

func computePathStats(nodes []*provenance.Node, edges []*provenance.Edge) (avg, max float64) {
	if len(nodes) <= 1 {
		return 0, 0
	}

	// Build adjacency
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.Source] = append(adj[e.Source], e.Target)
	}

	// Find roots (nodes with no incoming edges)
	targets := make(map[string]bool)
	for _, e := range edges {
		targets[e.Target] = true
	}
	var roots []string
	for _, n := range nodes {
		if !targets[n.ID] {
			roots = append(roots, n.ID)
		}
	}
	if len(roots) == 0 && len(nodes) > 0 {
		roots = append(roots, nodes[0].ID)
	}

	// BFS from each root, sum path lengths
	var totalLen, count float64
	visited := make(map[string]bool)

	for _, root := range roots {
		type bfsItem struct {
			id    string
			depth float64
		}
		queue := []bfsItem{{root, 0}}
		visited[root] = true

		for len(queue) > 0 {
			item := queue[0]
			queue = queue[1:]

			if item.depth > 0 {
				totalLen += item.depth
				count++
			}
			if item.depth > max {
				max = item.depth
			}

			for _, next := range adj[item.id] {
				if !visited[next] {
					visited[next] = true
					queue = append(queue, bfsItem{next, item.depth + 1})
				}
			}
		}
	}

	if count > 0 {
		avg = totalLen / count
	}
	return
}

// Entropy.

func computeEntropy(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := sum(values)
	if total == 0 {
		return 0
	}
	var ent float64
	for _, v := range values {
		p := v / total
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent / math.Log2(float64(len(values))) // normalised [0,1]
}

// Stats helpers.

func avg(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	return sum(v) / float64(len(v))
}

func sum(v []float64) float64 {
	var s float64
	for _, x := range v {
		s += x
	}
	return s
}

func maxFloat(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	m := v[0]
	for _, x := range v[1:] {
		if x > m {
			m = x
		}
	}
	return m
}

func stddev(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	m := avg(v)
	var sumSq float64
	for _, x := range v {
		d := x - m
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(v)-1))
}

// Vector operations.

// Distance computes Euclidean distance between two feature vectors.
func (fv FeatureVector) Distance(other FeatureVector) float64 {
	var d float64
	for i := 0; i < int(NumFeatures); i++ {
		diff := fv[i] - other[i]
		d += diff * diff
	}
	return math.Sqrt(d)
}

// Normalise scales all features to [0, 1] using given min/max.
func (fv *FeatureVector) Normalise(mins, maxs [NumFeatures]float64) {
	for i := 0; i < int(NumFeatures); i++ {
		r := maxs[i] - mins[i]
		if r > 0 {
			fv[i] = (fv[i] - mins[i]) / r
		}
	}
}

// FeatureReport generates a human-readable feature summary.
func FeatureReport(fv FeatureVector) []string {
	names := FeatureNames()
	report := make([]string, NumFeatures)
	for i := 0; i < int(NumFeatures); i++ {
		report[i] = names[i]
	}
	// Sort by feature name for consistent output
	sort.Strings(report)
	return report
}
