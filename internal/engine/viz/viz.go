// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package viz provides a lightweight visualization backend for ProvidAPT.
//
// Features:
//  1. Subgraph slice — extract 3-hop neighbourhood by alert ID
//  2. Cytoscape.js/D3.js JSON output
//  3. Timeline replay — timestamp-filtered attack path reconstruction
package viz

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Cytoscape.js graph format
// ═══════════════════════════════════════════════════════════════

// CytoGraph is the top-level graph structure for Cytoscape.js.
type CytoGraph struct {
	Data     CytoMeta      `json:"data"`
	Elements []CytoElement `json:"elements"`
}

// CytoMeta holds graph metadata.
type CytoMeta struct {
	Generated string `json:"generated"`
	NodeCount int    `json:"node_count"`
	EdgeCount int    `json:"edge_count"`
	AlertID   string `json:"alert_id,omitempty"`
	TimeRange string `json:"time_range,omitempty"`
}

// CytoElement is a node or edge in Cytoscape.js format.
type CytoElement struct {
	Group string       `json:"group"` // "nodes" or "edges"
	Data  CytoElemData `json:"data"`
}

// CytoElemData holds the element's data fields.
type CytoElemData struct {
	ID       string  `json:"id,omitempty"`
	Source   string  `json:"source,omitempty"`
	Target   string  `json:"target,omitempty"`
	Label    string  `json:"label,omitempty"`
	NodeType string  `json:"type,omitempty"`
	Class    string  `json:"class,omitempty"` // CSS class for styling
	Time     int64   `json:"time,omitempty"`  // timestamp for animation
	Score    float64 `json:"score,omitempty"`
}

// ─── VizEngine ────────────────────────────────────────────────────

// VizEngine builds visualisation data from the provenance graph.
// It can be populated manually via AddNode/AddEdge, or synced from a
// provenance.Graph via SyncFromGraph for real-time data access.
type VizEngine struct {
	mu    sync.Mutex
	graph *provenance.Graph // connected provenance graph (optional)
	nodes map[string]*NodeInfo
	edges []*EdgeInfo
}

// NodeInfo holds a node for visualization.
type NodeInfo struct {
	ID    string  `json:"id"`
	Type  string  `json:"type"`
	Label string  `json:"label"`
	Score float64 `json:"score,omitempty"`
}

// EdgeInfo holds an edge for visualization.
type EdgeInfo struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`
	Time     int64  `json:"time"`
}

// NewVizEngine creates a visualization engine.
func NewVizEngine() *VizEngine {
	return &VizEngine{
		nodes: make(map[string]*NodeInfo),
	}
}

// ─── Graph connection ─────────────────────────────────────────

// SetGraph sets the provenance graph to sync from. Call Sync() after
// setting the graph to populate the internal cache, or use SyncFromGraph
// for the combined operation.
func (ve *VizEngine) SetGraph(g *provenance.Graph) {
	ve.mu.Lock()
	defer ve.mu.Unlock()
	ve.graph = g
}

// Sync clears the internal cache and reloads all data from the connected
// provenance graph. Returns an error if no graph is connected.
func (ve *VizEngine) Sync() error {
	ve.mu.Lock()
	defer ve.mu.Unlock()

	if ve.graph == nil {
		return fmt.Errorf("viz: no graph connected, call SetGraph first")
	}

	// Clear existing data.
	ve.nodes = make(map[string]*NodeInfo)
	ve.edges = ve.edges[:0]

	// Copy nodes from the provenance graph.
	for _, n := range ve.graph.Nodes() {
		ve.nodes[n.ID] = &NodeInfo{
			ID:    n.ID,
			Type:  n.ProvType,
			Label: n.Label,
		}
	}

	// Copy edges from the provenance graph.
	for _, e := range ve.graph.Edges() {
		ve.edges = append(ve.edges, &EdgeInfo{
			Source:   e.Source,
			Target:   e.Target,
			Relation: e.Relation,
			Time:     e.Timestamp.UnixNano(),
		})
	}

	return nil
}

// SyncFromGraph sets the graph and syncs in one call.
func (ve *VizEngine) SyncFromGraph(g *provenance.Graph) error {
	ve.SetGraph(g)
	return ve.Sync()
}

// ─── Pagination options for subgraph extraction ───────────────

// SubgraphOpts controls optional behaviour of ExtractSubgraphWithOpts.
type SubgraphOpts struct {
	// Ctx carries a deadline or cancellation for long-running extractions
	// on large provenance graphs. When nil, context.Background() is used.
	Ctx context.Context

	// Limit caps the number of nodes returned. 0 = unlimited.
	Limit int

	// Offset skips the first N nodes from the result. 0 = start from beginning.
	Offset int
}

// AddNode registers a node for visualization.
func (ve *VizEngine) AddNode(id, ntype, label string, score float64) {
	ve.mu.Lock()
	defer ve.mu.Unlock()
	ve.nodes[id] = &NodeInfo{ID: id, Type: ntype, Label: label, Score: score}
}

// AddEdge registers an edge for visualization.
func (ve *VizEngine) AddEdge(source, target, relation string, timestamp int64) {
	ve.mu.Lock()
	defer ve.mu.Unlock()
	ve.edges = append(ve.edges, &EdgeInfo{
		Source: source, Target: target, Relation: relation, Time: timestamp,
	})
}

// ─── 3-hop subgraph extraction ─────────────────────────────────

// ExtractSubgraph returns a Cytoscape.js graph containing all nodes
// and edges within `maxHops` of the given seed nodes.
//
// BFS traversal from each seed node, following edges in both
// directions.
func (ve *VizEngine) ExtractSubgraph(seedIDs []string, maxHops int, timeStart, timeEnd int64) *CytoGraph {
	return ve.ExtractSubgraphWithOpts(seedIDs, maxHops, timeStart, timeEnd, SubgraphOpts{})
}

// ExtractSubgraphWithOpts is like ExtractSubgraph but supports
// pagination (Limit/Offset) and context-based cancellation via
// SubgraphOpts.
//
// When Limit is set, the returned graph contains at most Limit nodes
// (after applying Offset). Edges are limited to those connecting the
// returned nodes.
//
// The caller should periodically check ctx.Err() for cancellation when
// working with very large graphs.
func (ve *VizEngine) ExtractSubgraphWithOpts(seedIDs []string, maxHops int, timeStart, timeEnd int64, opts SubgraphOpts) *CytoGraph {
	ve.mu.Lock()
	defer ve.mu.Unlock()

	if maxHops <= 0 {
		maxHops = 3
	}

	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// BFS to find reachable nodes
	visited := make(map[string]int) // nodeID → depth
	queue := make([]string, 0)

	for _, seed := range seedIDs {
		if _, ok := ve.nodes[seed]; ok {
			visited[seed] = 0
			queue = append(queue, seed)
		}
	}

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			// Build what we have so far.
			return buildCytoGraph(ve.nodes, ve.edges, visited, timeStart, timeEnd)
		}

		current := queue[0]
		queue = queue[1:]
		depth := visited[current]

		if depth >= maxHops {
			continue
		}

		for _, edge := range ve.edges {
			// Time filter
			if timeStart > 0 && edge.Time < timeStart {
				continue
			}
			if timeEnd > 0 && edge.Time > timeEnd {
				continue
			}

			var neighbour string
			if edge.Source == current {
				neighbour = edge.Target
			} else if edge.Target == current {
				neighbour = edge.Source
			} else {
				continue
			}

			if _, seen := visited[neighbour]; !seen {
				if _, exists := ve.nodes[neighbour]; exists {
					visited[neighbour] = depth + 1
					queue = append(queue, neighbour)
				}
			}
		}
	}

	// Apply pagination (offset/limit) to visited nodes.
	visited = paginateVisited(visited, opts.Offset, opts.Limit)

	return buildCytoGraph(ve.nodes, ve.edges, visited, timeStart, timeEnd)
}

// paginateVisited applies offset and limit to a visited node set.
func paginateVisited(visited map[string]int, offset, limit int) map[string]int {
	if offset <= 0 && limit <= 0 {
		return visited
	}

	// Collect into a slice for deterministic ordering.
	type visit struct {
		id    string
		depth int
	}
	visitedSlice := make([]visit, 0, len(visited))
	for id, depth := range visited {
		visitedSlice = append(visitedSlice, visit{id, depth})
	}
	sort.Slice(visitedSlice, func(i, j int) bool {
		return visitedSlice[i].id < visitedSlice[j].id
	})

	// Apply offset.
	if offset > 0 {
		if offset >= len(visitedSlice) {
			return make(map[string]int)
		}
		visitedSlice = visitedSlice[offset:]
	}

	// Apply limit.
	if limit > 0 && limit < len(visitedSlice) {
		visitedSlice = visitedSlice[:limit]
	}

	// Rebuild map.
	paginated := make(map[string]int, len(visitedSlice))
	for _, v := range visitedSlice {
		paginated[v.id] = v.depth
	}
	return paginated
}

// buildCytoGraph constructs a CytoGraph from the given nodes, edges,
// visited set, and time range. The caller must hold ve.mu.
func buildCytoGraph(nodes map[string]*NodeInfo, edgeList []*EdgeInfo, visited map[string]int, timeStart, timeEnd int64) *CytoGraph {
	graph := &CytoGraph{
		Data: CytoMeta{
			Generated: time.Now().UTC().Format(time.RFC3339Nano),
			TimeRange: fmt.Sprintf("%d-%d", timeStart, timeEnd),
		},
	}

	// Add nodes
	for nodeID, depth := range visited {
		if n, ok := nodes[nodeID]; ok {
			class := "depth-" + fmt.Sprintf("%d", depth)
			if depth == 0 {
				class = "seed"
			}
			graph.Elements = append(graph.Elements, CytoElement{
				Group: "nodes",
				Data: CytoElemData{
					ID:       n.ID,
					Label:    n.Label,
					NodeType: n.Type,
					Class:    class,
					Score:    n.Score,
				},
			})
		}
	}

	// Add edges
	seenEdge := make(map[string]bool)
	for _, edge := range edgeList {
		if _, ok := visited[edge.Source]; !ok {
			continue
		}
		if _, ok := visited[edge.Target]; !ok {
			continue
		}
		// Time filter
		if timeStart > 0 && edge.Time < timeStart {
			continue
		}
		if timeEnd > 0 && edge.Time > timeEnd {
			continue
		}
		eKey := edge.Source + "|" + edge.Target + "|" + edge.Relation
		if seenEdge[eKey] {
			continue
		}
		seenEdge[eKey] = true

		graph.Elements = append(graph.Elements, CytoElement{
			Group: "edges",
			Data: CytoElemData{
				Source: edge.Source,
				Target: edge.Target,
				Label:  truncateLabel(edge.Relation),
				Class:  "edge-" + edge.Relation,
				Time:   edge.Time,
			},
		})
	}

	graph.Data.NodeCount = countNodes(graph.Elements)
	graph.Data.EdgeCount = countEdges(graph.Elements)

	return graph
}

// countEdgesFromVisited counts edges whose source and target are both
// in the visited node set. Used for early cancellation reporting.
func countEdgesFromVisited(edgeList []*EdgeInfo, visited map[string]int) int {
	count := 0
	for _, edge := range edgeList {
		if _, ok := visited[edge.Source]; ok {
			if _, ok := visited[edge.Target]; ok {
				count++
			}
		}
	}
	return count
}

// ─── Incremental / depth-range extraction ──────────────────────

// PartialResult holds a partial extraction result with a flag that tells
// the caller whether deeper BFS levels remain.  Useful for progressive
// (lazy) loading in a UI.
type PartialResult struct {
	Graph   *CytoGraph
	HasMore bool // true when deeper (unfetched) levels still exist
}

// ExtractPartial extracts nodes and edges within [0, maxDepth] from seed
// nodes, but caps the returned set to depthRange levels starting from
// startDepth.  The HasMore field tells the caller whether nodes at
// depth > startDepth+depthRange exist.
//
// Example — three calls to progressively load depth 0‑1, then 2, then 3:
//
//	r1 := ve.ExtractPartial(seeds, 3, 0, 1, SubgraphOpts{})
//	r2 := ve.ExtractPartial(seeds, 3, 2, 1, SubgraphOpts{})
//	r3 := ve.ExtractPartial(seeds, 3, 3, 1, SubgraphOpts{})
func (ve *VizEngine) ExtractPartial(seedIDs []string, maxHops, startDepth, depthRange int, opts SubgraphOpts) *PartialResult {
	ve.mu.Lock()
	defer ve.mu.Unlock()

	if maxHops <= 0 {
		maxHops = 3
	}
	if depthRange <= 0 {
		depthRange = 1
	}

	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// BFS to discover all reachable nodes (up to maxHops).
	visited := make(map[string]int)
	queue := make([]string, 0)

	for _, seed := range seedIDs {
		if _, ok := ve.nodes[seed]; ok {
			visited[seed] = 0
			queue = append(queue, seed)
		}
	}

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			break
		}
		current := queue[0]
		queue = queue[1:]
		depth := visited[current]

		if depth >= maxHops {
			continue
		}

		for _, edge := range ve.edges {
			var neighbour string
			if edge.Source == current {
				neighbour = edge.Target
			} else if edge.Target == current {
				neighbour = edge.Source
			} else {
				continue
			}
			if _, seen := visited[neighbour]; !seen {
				if _, exists := ve.nodes[neighbour]; exists {
					visited[neighbour] = depth + 1
					queue = append(queue, neighbour)
				}
			}
		}
	}

	// Keep only nodes in [startDepth, startDepth+depthRange).
	targetMax := startDepth + depthRange
	filtered := make(map[string]int)
	maxReached := 0
	for id, d := range visited {
		if d >= startDepth && d < targetMax {
			filtered[id] = d
		}
		if d > maxReached {
			maxReached = d
		}
	}

	hasMore := maxReached >= targetMax

	// Apply pagination on top.
	filtered = paginateVisited(filtered, opts.Offset, opts.Limit)

	return &PartialResult{
		Graph:   buildCytoGraph(ve.nodes, ve.edges, filtered, 0, 0),
		HasMore: hasMore,
	}
}

// ─── Timeline replay ──────────────────────────────────────────

// TimelineFrame represents a single frame in the attack replay.
type TimelineFrame struct {
	Time      int64         `json:"time"`
	TimeLabel string        `json:"time_label"`
	Nodes     []CytoElement `json:"nodes"`
	Edges     []CytoElement `json:"edges"`
}

// GenerateTimeline creates a sequence of timeline frames showing
// how the attack evolved step by step.
//
// Each frame adds the nodes and edges active at that time point.
// The frontend can animate through frames for "attack replay".
func (ve *VizEngine) GenerateTimeline(seedIDs []string, maxHops int, frameCount int) []*TimelineFrame {
	full := ve.ExtractSubgraph(seedIDs, maxHops, 0, 0)
	if frameCount <= 0 {
		frameCount = 10
	}

	// Collect all timestamps from edges
	var timestamps []int64
	edgeMap := make(map[int64][]CytoElement)
	for _, el := range full.Elements {
		if el.Group == "edges" && el.Data.Time > 0 {
			timestamps = append(timestamps, el.Data.Time)
			edgeMap[el.Data.Time] = append(edgeMap[el.Data.Time], el)
		}
	}
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})

	// Build frames — each frame adds a slice of edges
	frames := make([]*TimelineFrame, 0, frameCount)
	stepSize := len(timestamps) / frameCount
	if stepSize < 1 {
		stepSize = 1
	}

	allNodes := make(map[string]bool)
	allEdges := make(map[string]bool)

	// Add seed nodes in frame 0
	for _, el := range full.Elements {
		if el.Group == "nodes" && el.Data.Class == "seed" {
			allNodes[el.Data.ID] = true
		}
	}

	frames = append(frames, buildFrame(0, allNodes, allEdges, full.Elements))

	for i := 0; i < len(timestamps); i += stepSize {
		end := i + stepSize
		if end > len(timestamps) {
			end = len(timestamps)
		}

		for _, t := range timestamps[i:end] {
			for _, el := range edgeMap[t] {
				allEdges[el.Data.Source+"|"+el.Data.Target] = true
				allNodes[el.Data.Source] = true
				allNodes[el.Data.Target] = true
			}
		}

		label := "T+" + fmt.Sprintf("%d", i/stepSize)
		if i < len(timestamps) {
			label = fmt.Sprintf("t=%d", timestamps[i])
		}

		frames = append(frames, &TimelineFrame{
			Time:      int64(i),
			TimeLabel: label,
			Nodes:     filterElements(full.Elements, "nodes", allNodes),
			Edges:     filterEdges(full.Elements, allEdges),
		})
	}

	return frames
}

// ─── Helpers ──────────────────────────────────────────────────

func countNodes(elements []CytoElement) int {
	n := 0
	for _, el := range elements {
		if el.Group == "nodes" {
			n++
		}
	}
	return n
}

func countEdges(elements []CytoElement) int {
	n := 0
	for _, el := range elements {
		if el.Group == "edges" {
			n++
		}
	}
	return n
}

func buildFrame(frameIdx int, nodes map[string]bool, edges map[string]bool, all []CytoElement) *TimelineFrame {
	return &TimelineFrame{
		Time:      int64(frameIdx),
		TimeLabel: fmt.Sprintf("Frame %d", frameIdx),
		Nodes:     filterElements(all, "nodes", nodes),
		Edges:     filterEdges(all, edges),
	}
}

func filterElements(all []CytoElement, group string, keep map[string]bool) []CytoElement {
	var out []CytoElement
	for _, el := range all {
		if el.Group != group {
			continue
		}
		if keep[el.Data.ID] {
			out = append(out, el)
		}
	}
	return out
}

func filterEdges(all []CytoElement, keep map[string]bool) []CytoElement {
	var out []CytoElement
	for _, el := range all {
		if el.Group != "edges" {
			continue
		}
		key := el.Data.Source + "|" + el.Data.Target
		if keep[key] {
			out = append(out, el)
		}
	}
	return out
}

func truncateLabel(rel string) string {
	switch rel {
	case "prov:used":
		return "used"
	case "prov:wasGeneratedBy":
		return "created"
	case "prov:wasInformedBy":
		return "forked"
	case "prov:wasDerivedFrom":
		return "derived"
	default:
		if len(rel) > 16 {
			return rel[:16] + "..."
		}
		return rel
	}
}

// ─── DOT export ─────────────────────────────────────────────

// CytoToDOT converts a CytoGraph to Graphviz DOT format for rendering
// with tools like `dot`, `neato`, or Graphviz online viewers.
func CytoToDOT(g *CytoGraph) string {
	var b strings.Builder
	b.WriteString("digraph ProvidAPT {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box, style=rounded, fontname=monospace];\n")
	b.WriteString("  edge [fontname=monospace, fontsize=10];\n\n")

	// Nodes
	for _, elem := range g.Elements {
		if elem.Group != "nodes" {
			continue
		}
		id := elem.Data.ID
		label := elem.Data.Label
		if label == "" {
			label = id
		}
		ntype := elem.Data.NodeType
		color := nodeColor(ntype)
		b.WriteString(fmt.Sprintf("  %q [label=%q, fillcolor=%q, style=filled];\n", id, label, color))
	}

	b.WriteString("\n")

	// Edges (dedup by counting multi-edges)
	edgeCount := make(map[string]int)
	for _, elem := range g.Elements {
		if elem.Group != "edges" {
			continue
		}
		key := fmt.Sprintf("%s->%s", elem.Data.Source, elem.Data.Target)
		edgeCount[key]++
	}
	seen := make(map[string]bool)
	for _, elem := range g.Elements {
		if elem.Group != "edges" {
			continue
		}
		key := fmt.Sprintf("%s->%s", elem.Data.Source, elem.Data.Target)
		if seen[key] {
			continue
		}
		seen[key] = true
		rel := elem.Data.Label
		if rel == "" {
			rel = "related"
		}
		count := edgeCount[key]
		label := rel
		if count > 1 {
			label = fmt.Sprintf("%s (x%d)", rel, count)
		}
		b.WriteString(fmt.Sprintf("  %q -> %q [label=%q];\n",
			elem.Data.Source, elem.Data.Target, label))
	}

	b.WriteString("}\n")
	return b.String()
}

// nodeColor returns a DOT fillcolor based on node type.
func nodeColor(ntype string) string {
	switch ntype {
	case "process", "proc":
		return "#ADD8E6" // light blue
	case "file":
		return "#90EE90" // light green
	case "network", "net":
		return "#FFB6C1" // light pink
	case "socket":
		return "#FFD700" // gold
	case "dns":
		return "#DDA0DD" // plum
	case "alert":
		return "#FF6347" // tomato (red)
	default:
		return "#F5F5F5" // white smoke
	}
}
