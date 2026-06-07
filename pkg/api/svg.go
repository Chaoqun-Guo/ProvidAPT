// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// SVG generation for provenance attack paths
//
// Generates a simple top-down tree SVG showing the attack path:
//   - Process nodes in blue
//   - File nodes in green
//   - Network nodes in red
//   - Credential nodes in orange
//   - Edges as directed arrows with labels
// ═══════════════════════════════════════════════════════════════

type svgLayout struct {
	nodes   []svgNode
	edges   []svgEdge
	width   int
	height  int
}

type svgNode struct {
	id    string
	label string
	typ   string
	x     int
	y     int
}

type svgEdge struct {
	src string
	dst string
	rel string
}

const (
	nodeW = 140
	nodeH = 36
	xPad  = 30
	yPad  = 60
	topY  = 40
)

// generateAlertSVG creates an SVG representation of the attack path.
func generateAlertSVG(alertID string, graph *provenance.Graph) ([]byte, error) {
	// Collect a subgraph relevant to this alert
	allNodes := graph.Nodes()
	allEdges := graph.Edges()

	if len(allNodes) == 0 {
		return defaultSVG("No data available"), nil
	}

	// Build layout
	layout := layoutGraph(allNodes, allEdges)
	return renderSVG(layout), nil
}

// layoutGraph positions nodes in a top-down tree.
func layoutGraph(nodes []*provenance.Node, edges []*provenance.Edge) *svgLayout {
	lay := &svgLayout{}

	// Build adjacency for topo sort
	outDegree := make(map[string]int)
	inDegree := make(map[string]int)
	for _, e := range edges {
		outDegree[e.Source]++
		inDegree[e.Target]++
	}

	// Simple layout: layer nodes by depth (BFS from roots)
	roots := findRoots(nodes, edges)
	layers := bfsLayers(roots, edges)

	// Position nodes
	y := topY
	for _, layer := range layers {
		x := xPad
		for _, id := range layer {
			n := findNodeByID(nodes, id)
			if n == nil {
				continue
			}
			lay.nodes = append(lay.nodes, svgNode{
				id: n.ID, label: truncate(n.Label, 18),
				typ: n.Subtype, x: x, y: y,
			})
			x += nodeW + xPad
		}
		y += nodeH + yPad
	}
	lay.height = y
	lay.width = maxInt(xPad+nodeW, len(layers[0])*(nodeW+xPad)+xPad)

	// Collect edges for rendering
	for _, e := range edges {
		lay.edges = append(lay.edges, svgEdge{
			src: e.Source, dst: e.Target, rel: shortRel(e.Relation),
		})
	}
	return lay
}

func findRoots(nodes []*provenance.Node, edges []*provenance.Edge) []string {
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
	return roots
}

func bfsLayers(roots []string, edges []*provenance.Edge) [][]string {
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.Source] = append(adj[e.Source], e.Target)
	}
	var layers [][]string
	seen := make(map[string]bool)
	queue := roots
	for len(queue) > 0 {
		layers = append(layers, queue)
		var next []string
		for _, id := range queue {
			seen[id] = true
			for _, tgt := range adj[id] {
				if !seen[tgt] {
					next = append(next, tgt)
					seen[tgt] = true
				}
			}
		}
		queue = next
	}
	return layers
}

// ── SVG rendering ───────────────────────────────────────────

func renderSVG(lay *svgLayout) []byte {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">
<style>
  .node-process rect { fill: #4A90D9; rx: 6; }
  .node-file rect    { fill: #50B86C; rx: 6; }
  .node-network rect { fill: #E24C4C; rx: 6; }
  .node-credential rect { fill: #E8A838; rx: 6; }
  .node-default rect { fill: #999; rx: 6; }
  .node text { fill: white; font: 12px monospace; text-anchor: middle; dominant-baseline: central; }
  .edge line { stroke: #666; stroke-width: 1.5; marker-end: url(#arrow); }
  .edge-used line { stroke: #4A90D9; }
  .edge-created line { stroke: #50B86C; }
  .edge-forked line { stroke: #E8A838; }
  .edge text { fill: #888; font: 10px monospace; text-anchor: middle; }
  .title { fill: #333; font: 14px sans-serif; font-weight: bold; }
</style>
<defs>
  <marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto">
    <path d="M0,0 L10,5 L0,10 Z" fill="#666"/>
  </marker>
</defs>
<text x="15" y="20" class="title">ProvidAPT — Attack Path</text>
`, lay.width, lay.height, lay.width, lay.height))

	// Build node lookup for edge rendering
	nodeMap := make(map[string]svgNode)
	for _, n := range lay.nodes {
		nodeMap[n.id] = n
	}

	// Render edges
	for _, e := range lay.edges {
		src, ok := nodeMap[e.src]
		if !ok {
			continue
		}
		dst, ok := nodeMap[e.dst]
		if !ok {
			continue
		}
		x1 := src.x + nodeW/2
		y1 := src.y + nodeH
		x2 := dst.x + nodeW/2
		y2 := dst.y
		midY := (y1 + y2) / 2

		b.WriteString(fmt.Sprintf(`<g class="edge edge-%s">
  <line x1="%d" y1="%d" x2="%d" y2="%d"/>
  <text x="%d" y="%d">%s</text>
</g>
`, e.rel, x1, y1, x2, y2, x1, midY-4, e.rel))
	}

	// Render nodes
	for _, n := range lay.nodes {
		class := "node-default"
		switch n.typ {
		case "process":
			class = "node-process"
		case "file":
			class = "node-file"
		case "network":
			class = "node-network"
		case "credential":
			class = "node-credential"
		}
		b.WriteString(fmt.Sprintf(`<g class="node %s">
  <rect x="%d" y="%d" width="%d" height="%d"/>
  <text x="%d" y="%d">%s</text>
</g>
`, class, n.x, n.y, nodeW, nodeH, n.x+nodeW/2, n.y+nodeH/2, escapeXML(n.label)))
	}

	b.WriteString("</svg>\n")
	return []byte(b.String())
}

func defaultSVG(msg string) []byte {
	return []byte(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="400" height="100">
  <text x="20" y="40" font-family="monospace" font-size="14" fill="#666">%s</text>
</svg>`, escapeXML(msg)))
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// ── Helpers ─────────────────────────────────────────────────

func findNodeByID(nodes []*provenance.Node, id string) *provenance.Node {
	for _, n := range nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
