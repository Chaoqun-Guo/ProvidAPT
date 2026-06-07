// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package graphsketch

import (
	"math"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════
// Graph sketching — computes lightweight feature vectors from a
// provenance graph snapshot.
// ═══════════════════════════════════════════════════════════════════

// SketchComputer computes feature vectors from graph snapshots.
type SketchComputer struct{}

// NewSketchComputer creates a sketch computer.
func NewSketchComputer() *SketchComputer {
	return &SketchComputer{}
}

// ── Main entry point ─────────────────────────────────────────────

// Compute produces a full GraphFeatureVector from nodes and edges.
func (sc *SketchComputer) Compute(nodes []SketchNode, edges []SketchEdge) *GraphFeatureVector {
	fv := &GraphFeatureVector{
		NodeCount:     len(nodes),
		EdgeCount:     len(edges),
		NodeTypeDist:  make(map[string]int),
		EdgeTypeDist:  make(map[string]int),
		DegreeDist:    make(DegreeDistribution),
		InDegreeDist:  make(DegreeDistribution),
		OutDegreeDist: make(DegreeDistribution),
	}

	if len(nodes) == 0 {
		return fv
	}

	// 1. Compute degree information.
	inDeg := make(map[string]int, len(nodes))
	outDeg := make(map[string]int, len(nodes))

	for _, e := range edges {
		outDeg[e.Source]++
		inDeg[e.Target]++
		fv.EdgeTypeDist[e.Relation]++
	}

	for _, n := range nodes {
		fv.NodeTypeDist[n.Type]++
		in := inDeg[n.ID]
		out := outDeg[n.ID]
		total := in + out

		fv.DegreeDist[total]++
		fv.InDegreeDist[in]++
		fv.OutDegreeDist[out]++
	}

	// 2. Degree statistics.
	fv.DegreeStats = computeDistributionStats(fv.DegreeDist)
	fv.InDegreeStats = computeDistributionStats(fv.InDegreeDist)
	fv.OutDegreeStats = computeDistributionStats(fv.OutDegreeDist)

	// 3. Global metrics.
	fv.Density = computeDensity(len(nodes), len(edges))
	fv.InOutRatio = computeInOutRatio(inDeg, outDeg)

	// 4. Path statistics via BFS from root nodes.
	fv.PathStats = computePathStats(nodes, edges, outDeg, inDeg)

	return fv
}

// ── Degree statistics ────────────────────────────────────────────

func computeDistributionStats(dist DegreeDistribution) DistributionStats {
	if len(dist) == 0 {
		return DistributionStats{}
	}

	// Expand to sorted degree values.
	var degrees []int
	var totalWeight int
	for deg, count := range dist {
		for i := 0; i < count; i++ {
			degrees = append(degrees, deg)
		}
		totalWeight += count
	}
	if len(degrees) == 0 {
		return DistributionStats{}
	}

	sort.Ints(degrees)

	min := degrees[0]
	max := degrees[len(degrees)-1]

	// Mean.
	var sum int
	for _, d := range degrees {
		sum += d
	}
	mean := float64(sum) / float64(len(degrees))

	// Median.
	median := degrees[len(degrees)/2]

	// Standard deviation.
	var varianceSum float64
	for _, d := range degrees {
		diff := float64(d) - mean
		varianceSum += diff * diff
	}
	stdDev := math.Sqrt(varianceSum / float64(len(degrees)))

	return DistributionStats{
		Min:    min,
		Max:    max,
		Mean:   mean,
		Median: median,
		StdDev: stdDev,
	}
}

// ── Global metrics ───────────────────────────────────────────────

func computeDensity(nodeCount, edgeCount int) float64 {
	if nodeCount <= 1 {
		return 0
	}
	maxEdges := nodeCount * (nodeCount - 1)
	if maxEdges == 0 {
		return 0
	}
	return float64(edgeCount) / float64(maxEdges)
}

func computeInOutRatio(inDeg, outDeg map[string]int) float64 {
	var totalIn, totalOut int
	for _, d := range inDeg {
		totalIn += d
	}
	for _, d := range outDeg {
		totalOut += d
	}
	if totalOut == 0 {
		return 0
	}
	return float64(totalIn) / float64(totalOut)
}

// ── Path statistics ──────────────────────────────────────────────

func computePathStats(nodes []SketchNode, edges []SketchEdge, outDeg, inDeg map[string]int) PathStats {
	// Build adjacency list.
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.Source] = append(adj[e.Source], e.Target)
	}

	// Identify root nodes (no incoming edges).
	nodeSet := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		nodeSet[n.ID] = true
	}
	var roots []string
	for _, n := range nodes {
		if inDeg[n.ID] == 0 {
			roots = append(roots, n.ID)
		}
	}

	// If no roots found (cyclic or all nodes have in-degree > 0),
	// use all nodes as starting points.
	if len(roots) == 0 {
		roots = make([]string, 0, len(nodes))
		for _, n := range nodes {
			roots = append(roots, n.ID)
		}
	}

	// BFS from each root to find max depth, avg depth, and components.
	visited := make(map[string]bool)
	var maxDepth int
	var depthSum int
	var depthCount int
	var longestPath []string
	componentCount := 0

	for _, root := range roots {
		if visited[root] {
			continue
		}

		// BFS for this component.
		type bfsItem struct {
			id    string
			depth int
			path  []string
		}

		queue := []bfsItem{{id: root, depth: 0, path: []string{root}}}
		visited[root] = true
		componentCount++

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]

			depthSum += curr.depth
			depthCount++

			if curr.depth > maxDepth {
				maxDepth = curr.depth
				longestPath = curr.path
			}

			for _, neighbor := range adj[curr.id] {
				if !visited[neighbor] && nodeSet[neighbor] {
					visited[neighbor] = true
					newPath := make([]string, len(curr.path)+1)
					copy(newPath, curr.path)
					newPath[len(curr.path)] = neighbor
					queue = append(queue, bfsItem{
						id:    neighbor,
						depth: curr.depth + 1,
						path:  newPath,
					})
				}
			}
		}
	}

	avgDepth := 0.0
	if depthCount > 0 {
		avgDepth = float64(depthSum) / float64(depthCount)
	}

	return PathStats{
		MaxDepth:         maxDepth,
		AvgDepth:         avgDepth,
		ComponentCount:   componentCount,
		LongestPathNodes: longestPath,
	}
}

// ── Convenience constructors ─────────────────────────────────────

// ComputeFromGraph is a one-shot convenience function to compute a
// feature vector from raw slices.
func ComputeFromGraph(nodes []SketchNode, edges []SketchEdge) *GraphFeatureVector {
	return NewSketchComputer().Compute(nodes, edges)
}

// ── Vector comparison ────────────────────────────────────────────

// CosineSimilarity computes the cosine similarity between two feature
// vectors based on their degree distributions.
// Returns a value in [-1, 1] where 1 = identical distributions.
func CosineSimilarity(a, b *GraphFeatureVector) float64 {
	if a == nil || b == nil {
		return 0
	}

	// Use degree distribution as the feature vector.
	// Convert to ordered slices.
	keys := make(map[int]bool)
	for k := range a.DegreeDist {
		keys[k] = true
	}
	for k := range b.DegreeDist {
		keys[k] = true
	}

	var sortedKeys []int
	for k := range keys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Ints(sortedKeys)

	var dot, normA, normB float64
	for _, k := range sortedKeys {
		va := float64(a.DegreeDist[k])
		vb := float64(b.DegreeDist[k])
		dot += va * vb
		normA += va * va
		normB += vb * vb
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// VectorDiff returns the element-wise absolute difference between two
// feature vectors as a new vector. Used for delta-based detection.
func VectorDiff(a, b *GraphFeatureVector) *GraphFeatureVector {
	if a == nil || b == nil {
		return nil
	}

	diff := &GraphFeatureVector{
		DegreeDist:    make(DegreeDistribution),
		InDegreeDist:  make(DegreeDistribution),
		OutDegreeDist: make(DegreeDistribution),
	}

	diff.NodeCount = absInt(a.NodeCount - b.NodeCount)
	diff.EdgeCount = absInt(a.EdgeCount - b.EdgeCount)
	diff.Density = math.Abs(a.Density - b.Density)
	diff.InOutRatio = math.Abs(a.InOutRatio - b.InOutRatio)

	// Merge keys from both.
	allKeys := make(map[int]bool)
	for k := range a.DegreeDist {
		allKeys[k] = true
	}
	for k := range b.DegreeDist {
		allKeys[k] = true
	}
	for k := range allKeys {
		va := a.DegreeDist[k]
		vb := b.DegreeDist[k]
		diff.DegreeDist[k] = absInt(va - vb)
	}

	return diff
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
