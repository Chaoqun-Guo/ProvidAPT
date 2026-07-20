// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

type svgLayout struct {
	nodes    []svgNode
	edges    []svgEdge
	width    int
	height   int
	scope    string
	truncate bool
}

type svgNode struct {
	id      string
	label   string
	detail1 string
	detail2 string
	typ     string
	x       int
	y       int
}

type svgEdge struct {
	src     string
	dst     string
	rel     string
	event   string
	summary string
	detail  string
}

const (
	nodeW = 220
	nodeH = 70
	xPad  = 36
	yPad  = 78
	topY  = 56
)

func generateAlertSVG(alertID string, graph *provenance.Graph) []byte {
	nodes, edges, truncated := focusedGraph(alertID, graph, 4, 80, 120)
	if len(nodes) == 0 {
		return defaultSVG("No provenance events are available yet")
	}
	layout := layoutGraph(nodes, edges)
	layout.scope = alertID
	layout.truncate = truncated
	return renderSVG(layout)
}

func focusedGraph(startID string, graph *provenance.Graph, maxDepth, maxNodes, maxEdges int) ([]*provenance.Node, []*provenance.Edge, bool) {
	allNodes := graph.Nodes()
	allEdges := graph.Edges()
	if startID == "" {
		return capGraph(allNodes, allEdges, maxNodes, maxEdges)
	}
	if _, ok := graph.LookupNode(startID); !ok {
		return capGraph(allNodes, allEdges, maxNodes, maxEdges)
	}

	nodeMap := map[string]*provenance.Node{}
	edgeMap := map[string]*provenance.Edge{}
	queue := []string{startID}
	depth := map[string]int{startID: 0}
	truncated := false

	if n, ok := graph.LookupNode(startID); ok {
		nodeMap[startID] = n
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if depth[id] >= maxDepth {
			continue
		}
		for _, e := range allEdges {
			if e.Source != id && e.Target != id {
				continue
			}
			if len(edgeMap) >= maxEdges {
				truncated = true
				continue
			}
			edgeMap[e.ID] = e
			for _, nextID := range []string{e.Source, e.Target} {
				if _, ok := nodeMap[nextID]; ok {
					continue
				}
				if len(nodeMap) >= maxNodes {
					truncated = true
					continue
				}
				if n, ok := graph.LookupNode(nextID); ok {
					nodeMap[nextID] = n
					depth[nextID] = depth[id] + 1
					queue = append(queue, nextID)
				}
			}
		}
	}

	nodes := make([]*provenance.Node, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, n)
	}
	edges := make([]*provenance.Edge, 0, len(edgeMap))
	for _, e := range edgeMap {
		if nodeMap[e.Source] != nil && nodeMap[e.Target] != nil {
			edges = append(edges, e)
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(edges, func(i, j int) bool { return edges[i].Timestamp.Before(edges[j].Timestamp) })
	return nodes, edges, truncated
}

func capGraph(nodes []*provenance.Node, edges []*provenance.Edge, maxNodes, maxEdges int) ([]*provenance.Node, []*provenance.Edge, bool) {
	truncated := len(nodes) > maxNodes || len(edges) > maxEdges
	if len(nodes) > maxNodes {
		nodes = nodes[:maxNodes]
	}
	allowed := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		allowed[n.ID] = true
	}
	filtered := make([]*provenance.Edge, 0, minInt(len(edges), maxEdges))
	for _, e := range edges {
		if allowed[e.Source] && allowed[e.Target] {
			filtered = append(filtered, e)
			if len(filtered) >= maxEdges {
				truncated = true
				break
			}
		}
	}
	return nodes, filtered, truncated
}

func layoutGraph(nodes []*provenance.Node, edges []*provenance.Edge) *svgLayout {
	lay := &svgLayout{}
	roots := findRoots(nodes, edges)
	layers := bfsLayers(roots, edges)

	y := topY
	maxLayer := 1
	for _, layer := range layers {
		maxLayer = maxInt(maxLayer, len(layer))
		x := xPad
		for _, id := range layer {
			n := findNodeByID(nodes, id)
			if n == nil {
				continue
			}
			lay.nodes = append(lay.nodes, svgNode{
				id:      n.ID,
				label:   truncate(n.Label, 30),
				detail1: nodeDetailLine(n),
				detail2: nodeIdentityLine(n),
				typ:     n.Subtype,
				x:       x,
				y:       y,
			})
			x += nodeW + xPad
		}
		y += nodeH + yPad
	}

	lay.width = maxInt(820, maxLayer*(nodeW+xPad)+xPad)
	lay.height = y + maxInt(150, len(edges)*36+74)
	for _, e := range edges {
		lay.edges = append(lay.edges, svgEdge{
			src:     e.Source,
			dst:     e.Target,
			rel:     shortRel(e.Relation),
			event:   stringAttr(e.Attributes, "event", shortRel(e.Relation)),
			summary: edgeSummary(e),
			detail:  edgeDetail(e),
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
	sort.Strings(roots)
	return roots
}

func bfsLayers(roots []string, edges []*provenance.Edge) [][]string {
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.Source] = append(adj[e.Source], e.Target)
	}
	for src := range adj {
		sort.Strings(adj[src])
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

func renderSVG(lay *svgLayout) []byte {
	var b strings.Builder
	scope := "Process activity, target entity, observed event, and collected attributes"
	if strings.TrimSpace(lay.scope) != "" {
		scope = "Focused scope: " + lay.scope
	}
	if lay.truncate {
		scope += " (truncated for readability)"
	}
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">
<style>
  .bg { fill: #0d1117; }
  .node rect { stroke-width: 1.2; rx: 8; }
  .node-process rect { fill: #0f2747; stroke: #58a6ff; }
  .node-file rect { fill: #12351f; stroke: #3fb950; }
  .node-network rect { fill: #3a1a1a; stroke: #f85149; }
  .node-credential rect { fill: #3a2a1a; stroke: #d29922; }
  .node-default rect { fill: #1f232a; stroke: #8b949e; }
  .node .label { fill: #f0f6fc; font: 12px monospace; font-weight: 700; }
  .node .meta { fill: #8b949e; font: 10px monospace; }
  .edge line { stroke: #8b949e; stroke-width: 1.5; marker-end: url(#arrow); }
  .edge-used line { stroke: #58a6ff; }
  .edge-created line { stroke: #3fb950; }
  .edge-forked line { stroke: #d29922; }
  .edge text { fill: #f0f6fc; font: 10px monospace; text-anchor: middle; paint-order: stroke; stroke: #0d1117; stroke-width: 3px; }
  .title { fill: #f0f6fc; font: 16px sans-serif; font-weight: bold; }
  .subtitle { fill: #8b949e; font: 11px sans-serif; }
  .event-table text { fill: #c9d1d9; font: 11px monospace; }
  .event-table .header { fill: #58a6ff; font-weight: 700; }
  .event-table rect { fill: #161b22; stroke: #30363d; rx: 8; }
  .event-row rect { fill: #0d1117; stroke: #21262d; rx: 6; }
</style>
<defs>
  <marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto">
    <path d="M0,0 L10,5 L0,10 Z" fill="#8b949e"/>
  </marker>
</defs>
<rect class="bg" x="0" y="0" width="%d" height="%d"/>
<text x="18" y="22" class="title">ProvidAPT Provenance Trace</text>
<text x="18" y="40" class="subtitle">%s</text>
`, lay.width, lay.height, lay.width, lay.height, lay.width, lay.height, escapeXML(scope))

	nodeMap := make(map[string]svgNode)
	for _, n := range lay.nodes {
		nodeMap[n.id] = n
	}
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
		fmt.Fprintf(&b, `<g class="edge edge-%s">
  <line x1="%d" y1="%d" x2="%d" y2="%d"/>
  <text x="%d" y="%d">%s</text>
</g>
`, e.rel, x1, y1, x2, y2, x1, midY-4, escapeXML(e.event))
	}

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
		fmt.Fprintf(&b, `<g class="node %s">
  <rect x="%d" y="%d" width="%d" height="%d"/>
  <text class="label" x="%d" y="%d">%s</text>
  <text class="meta" x="%d" y="%d">%s</text>
  <text class="meta" x="%d" y="%d">%s</text>
</g>
`, class, n.x, n.y, nodeW, nodeH, n.x+10, n.y+21, escapeXML(n.label),
			n.x+10, n.y+41, escapeXML(n.detail1), n.x+10, n.y+57, escapeXML(n.detail2))
	}

	renderEventTable(&b, lay)
	b.WriteString("</svg>\n")
	return []byte(b.String())
}

func renderEventTable(b *strings.Builder, lay *svgLayout) {
	tableY := topY
	for _, n := range lay.nodes {
		tableY = maxInt(tableY, n.y+nodeH)
	}
	tableY += 50
	tableH := maxInt(110, len(lay.edges)*36+58)
	fmt.Fprintf(b, `<g class="event-table">
  <rect x="18" y="%d" width="%d" height="%d"/>
  <text class="header" x="34" y="%d">Event Structure</text>
`, tableY, lay.width-36, tableH, tableY+24)
	if len(lay.edges) == 0 {
		fmt.Fprintf(b, `  <text x="34" y="%d">No edges are available for this trace.</text>
</g>
`, tableY+52)
		return
	}
	for i, e := range lay.edges {
		y := tableY + 38 + i*36
		fmt.Fprintf(b, `<g class="event-row">
  <rect x="30" y="%d" width="%d" height="30"/>
  <text x="42" y="%d">#%02d %-14s %s</text>
  <text x="42" y="%d">%s</text>
</g>
`, y, lay.width-60, y+13, i+1, escapeXML(e.event), escapeXML(e.summary), y+26, escapeXML(e.detail))
	}
	b.WriteString("</g>\n")
}

func defaultSVG(msg string) []byte {
	return []byte(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="520" height="120">
  <rect x="0" y="0" width="520" height="120" fill="#0d1117"/>
  <text x="20" y="42" font-family="monospace" font-size="14" fill="#c9d1d9">%s</text>
</svg>`, escapeXML(msg)))
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

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
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func nodeDetailLine(n *provenance.Node) string {
	switch n.Subtype {
	case "process":
		return compactJoin([]string{kv("pid", n.Attributes["pid"]), kv("uid", n.Attributes["uid"]), kv("comm", n.Attributes["comm"])})
	case "file":
		return compactJoin([]string{kv("inode", n.Attributes["inode"]), kv("dev", n.Attributes["device"]), kv("mode", n.Attributes["mode"])})
	case "network":
		return compactJoin([]string{kv("endpoint", n.Attributes["endpoint"]), kv("proto", n.Attributes["protocol"])})
	default:
		return "type=" + n.Subtype
	}
}

func nodeIdentityLine(n *provenance.Node) string {
	switch n.Subtype {
	case "process":
		return truncate(stringAttr(n.Attributes, "exe_path", n.ID), 38)
	case "file":
		return truncate(stringAttr(n.Attributes, "pathname", n.ID), 38)
	default:
		return truncate(n.ID, 38)
	}
}

func edgeSummary(e *provenance.Edge) string {
	return fmt.Sprintf("%s -> %s (%s)", truncate(e.Source, 22), truncate(e.Target, 22), shortRel(e.Relation))
}

func edgeDetail(e *provenance.Edge) string {
	keys := []string{"pid", "comm", "path", "inode", "f_flags", "child_pid", "prev"}
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		if text := kv(key, e.Attributes[key]); text != "" {
			parts = append(parts, text)
		}
	}
	if len(parts) == 0 {
		allKeys := make([]string, 0, len(e.Attributes))
		for key := range e.Attributes {
			allKeys = append(allKeys, key)
		}
		sort.Strings(allKeys)
		for _, key := range allKeys {
			if text := kv(key, e.Attributes[key]); text != "" {
				parts = append(parts, text)
			}
			if len(parts) >= 4 {
				break
			}
		}
	}
	return truncate(compactJoin(parts), 116)
}

func stringAttr(attrs map[string]interface{}, key, fallback string) string {
	if attrs == nil {
		return fallback
	}
	value, ok := attrs[key]
	if !ok || value == nil {
		return fallback
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" {
		return fallback
	}
	return text
}

func kv(key string, value interface{}) string {
	if value == nil {
		return ""
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" {
		return ""
	}
	return key + "=" + text
}

func compactJoin(parts []string) string {
	out := parts[:0]
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, " · ")
}
