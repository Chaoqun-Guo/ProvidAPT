// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package viz provides a lightweight visualization backend for ProvidAPT.
//
// Features:
//  1. Subgraph slice 鈥-extract 3-hop neighbourhood by alert ID
//  2. Cytoscape.js/D3.js JSON output
//  3. Timeline replay 鈥-timestamp-filtered attack path reconstruction
package viz

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺-// Cytoscape.js graph format
// 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺-
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

// 鈹€鈹€鈹€ VizEngine 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

// VizEngine builds visualisation data from the provenance graph.
type VizEngine struct {
	mu    sync.Mutex
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

// 鈹€鈹€鈹€ 3-hop subgraph extraction 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

// ExtractSubgraph returns a Cytoscape.js graph containing all nodes
// and edges within `maxHops` of the given seed nodes.
//
// BFS traversal from each seed node, following edges in both
// directions.
func (ve *VizEngine) ExtractSubgraph(seedIDs []string, maxHops int, timeStart, timeEnd int64) *CytoGraph {
	ve.mu.Lock()
	defer ve.mu.Unlock()

	if maxHops <= 0 {
		maxHops = 3
	}

	// BFS to find reachable nodes
	visited := make(map[string]int) // nodeID 鈫-depth
	queue := make([]string, 0)

	for _, seed := range seedIDs {
		if _, ok := ve.nodes[seed]; ok {
			visited[seed] = 0
			queue = append(queue, seed)
		}
	}

	for len(queue) > 0 {
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

	// Build Cytoscape.js output
	graph := &CytoGraph{
		Data: CytoMeta{
			Generated: time.Now().UTC().Format(time.RFC3339Nano),
			TimeRange: fmt.Sprintf("%d-%d", timeStart, timeEnd),
		},
	}

	// Add nodes
	for nodeID, depth := range visited {
		if n, ok := ve.nodes[nodeID]; ok {
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
	for _, edge := range ve.edges {
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

// 鈹€鈹€鈹€ Timeline replay 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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

	// Build frames 鈥-each frame adds a slice of edges
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

// 鈹€鈹€鈹€ Helpers 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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
