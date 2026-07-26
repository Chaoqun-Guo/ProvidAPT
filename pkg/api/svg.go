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
	nodes          []svgNode
	edges          []svgEdge
	clusters       []svgCluster
	width          int
	height         int
	graphH         int
	scope          string
	truncate       bool
	collapsedNodes int
}

type svgNode struct {
	id      string
	label   string
	detail1 string
	detail2 string
	typ     string
	x       int
	y       int
	w       int
	h       int
}

type svgEdge struct {
	src     string
	dst     string
	rel     string
	kind    string
	event   string
	summary string
	detail  string
	tree    bool
}

type svgEventGroup struct {
	key        string
	title      string
	edges      []svgEdge
	crossLinks int
}

type svgCluster struct {
	id      string
	title   string
	count   int
	typ     string
	depth   int
	x       int
	y       int
	w       int
	h       int
	members []string
}

const (
	minNodeW    = 240
	maxNodeW    = 520
	minNodeH    = 82
	xPad        = 36
	yPad        = 42
	layerGap    = 120
	topY        = 76
	minGraphH   = 320
	edgeLabelDX = 10
	clusterMin  = 5
	clusterKeep = 3
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
	depth, treeParent, orderedIDs := treeLayoutOrder(nodes, edges, roots)
	clusteredIDs, clusters := clusterSVGNodes(nodes, orderedIDs, depth)
	lay.clusters = clusters
	lay.collapsedNodes = len(orderedIDs) - len(clusteredIDs)
	if len(clusteredIDs) > 0 {
		orderedIDs = clusteredIDs
	}

	maxDepth := 0
	for _, id := range orderedIDs {
		maxDepth = maxInt(maxDepth, depth[id])
	}
	measured := make([]svgNode, 0, len(orderedIDs))
	colWidths := make([]int, maxDepth+1)
	for _, id := range orderedIDs {
		n := findNodeByID(nodes, id)
		if n == nil {
			continue
		}
		node := makeSVGNode(n, depth[id])
		measured = append(measured, node)
		colWidths[depth[id]] = maxInt(colWidths[depth[id]], node.w)
	}

	graphW := 0
	for depthIndex, width := range colWidths {
		graphW += width
		if depthIndex > 0 {
			graphW += layerGap
		}
	}
	lay.width = maxInt(1120, xPad*2+graphW)
	contentX := maxInt(xPad, (lay.width-graphW)/2)
	colX := make([]int, len(colWidths))
	x := contentX
	for i, width := range colWidths {
		colX[i] = x
		x += width + layerGap
	}
	y := topY
	for _, node := range measured {
		node.x = colX[depth[node.id]]
		node.y = y
		lay.nodes = append(lay.nodes, node)
		y += node.h + yPad
	}
	for i := range lay.clusters {
		cluster := &lay.clusters[i]
		cluster.x = colX[cluster.depth]
		cluster.y = y
		cluster.w = maxInt(minNodeW, colWidths[cluster.depth])
		cluster.h = 74
		y += cluster.h + yPad
	}

	graphH := y + 20
	lay.graphH = maxInt(minGraphH, graphH)
	usedTreeEdges := map[string]bool{}
	visibleNode := make(map[string]bool, len(lay.nodes))
	for _, node := range lay.nodes {
		visibleNode[node.id] = true
	}
	for _, e := range edges {
		if !visibleNode[e.Source] || !visibleNode[e.Target] {
			continue
		}
		tree := treeParent[e.Target] == e.Source && !usedTreeEdges[e.Source+"\x00"+e.Target]
		if tree {
			usedTreeEdges[e.Source+"\x00"+e.Target] = true
		}
		lay.edges = append(lay.edges, svgEdge{
			src:     e.Source,
			dst:     e.Target,
			rel:     shortRel(e.Relation),
			kind:    edgeKind(e),
			event:   stringAttr(e.Attributes, "event", shortRel(e.Relation)),
			summary: edgeSummary(e),
			detail:  edgeDetail(e),
			tree:    tree,
		})
	}
	lay.height = lay.graphH + eventTableHeight(lay.edges) + 50
	return lay
}

func clusterSVGNodes(nodes []*provenance.Node, orderedIDs []string, depth map[string]int) ([]string, []svgCluster) {
	byID := make(map[string]*provenance.Node, len(nodes))
	for _, node := range nodes {
		byID[node.ID] = node
	}
	type groupKey struct {
		depth int
		typ   string
	}
	groups := map[groupKey][]string{}
	for _, id := range orderedIDs {
		node := byID[id]
		if node == nil {
			continue
		}
		key := groupKey{depth: depth[id], typ: node.Subtype}
		groups[key] = append(groups[key], id)
	}
	collapsed := map[string]bool{}
	var clusters []svgCluster
	for key, ids := range groups {
		if len(ids) < clusterMin {
			continue
		}
		sort.Strings(ids)
		members := ids[clusterKeep:]
		for _, id := range members {
			collapsed[id] = true
		}
		clusters = append(clusters, svgCluster{
			id:      fmt.Sprintf("cluster:%d:%s", key.depth, key.typ),
			title:   fmt.Sprintf("%s cluster", displayType(key.typ)),
			count:   len(members),
			typ:     key.typ,
			depth:   key.depth,
			members: members,
		})
	}
	sort.Slice(clusters, func(i, j int) bool {
		if clusters[i].depth == clusters[j].depth {
			return clusters[i].typ < clusters[j].typ
		}
		return clusters[i].depth < clusters[j].depth
	})
	out := make([]string, 0, len(orderedIDs))
	for _, id := range orderedIDs {
		if !collapsed[id] {
			out = append(out, id)
		}
	}
	return out, clusters
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

func treeLayoutOrder(nodes []*provenance.Node, edges []*provenance.Edge, roots []string) (map[string]int, map[string]string, []string) {
	nodeIDs := make([]string, 0, len(nodes))
	nodeSet := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		nodeIDs = append(nodeIDs, n.ID)
		nodeSet[n.ID] = true
	}
	sort.Strings(nodeIDs)

	adj := make(map[string][]string)
	for _, e := range edges {
		if !nodeSet[e.Source] || !nodeSet[e.Target] {
			continue
		}
		adj[e.Source] = append(adj[e.Source], e.Target)
	}
	for src := range adj {
		sort.Strings(adj[src])
	}

	depth := make(map[string]int, len(nodes))
	treeParent := make(map[string]string, len(nodes))
	seen := make(map[string]bool, len(nodes))
	queue := append([]string{}, roots...)
	sort.Strings(queue)
	for _, root := range queue {
		seen[root] = true
		depth[root] = 0
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, child := range adj[id] {
			if seen[child] {
				continue
			}
			seen[child] = true
			treeParent[child] = id
			depth[child] = depth[id] + 1
			queue = append(queue, child)
		}
	}
	for _, id := range nodeIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		depth[id] = 0
		roots = append(roots, id)
	}

	var ordered []string
	visited := make(map[string]bool, len(nodes))
	var walk func(string)
	walk = func(id string) {
		if visited[id] {
			return
		}
		visited[id] = true
		ordered = append(ordered, id)
		children := append([]string{}, adj[id]...)
		sort.SliceStable(children, func(i, j int) bool {
			left := subtreeWeight(children[i], adj, treeParent, map[string]bool{})
			right := subtreeWeight(children[j], adj, treeParent, map[string]bool{})
			if left == right {
				return children[i] < children[j]
			}
			return left > right
		})
		for _, child := range children {
			if treeParent[child] == id {
				walk(child)
			}
		}
	}
	sort.Strings(roots)
	for _, root := range roots {
		walk(root)
	}
	for _, id := range nodeIDs {
		walk(id)
	}
	return depth, treeParent, ordered
}

func subtreeWeight(id string, adj map[string][]string, treeParent map[string]string, seen map[string]bool) int {
	if seen[id] {
		return 0
	}
	seen[id] = true
	total := 1
	for _, child := range adj[id] {
		if treeParent[child] == id {
			total += subtreeWeight(child, adj, treeParent, seen)
		}
	}
	return total
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
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" preserveAspectRatio="xMidYMin meet" style="max-width:100vw;height:auto;display:block;margin:0 auto;background:#0d1117;">
<style>
  .bg { fill: #0d1117; }
  .node rect { stroke-width: 1.2; rx: 8; }
  .cluster rect { fill: #161b22; stroke: #6e7681; stroke-width: 1.2; rx: 10; stroke-dasharray: 6 4; }
  .cluster .label { fill: #f0f6fc; font: 12px monospace; font-weight: 700; }
  .cluster .meta { fill: #8b949e; font: 10px monospace; }
  .node-process rect { fill: #0f2747; stroke: #58a6ff; }
  .node-file rect { fill: #12351f; stroke: #3fb950; }
  .node-network rect { fill: #3a1a1a; stroke: #f85149; }
  .node-credential rect { fill: #3a2a1a; stroke: #d29922; }
  .node-default rect { fill: #1f232a; stroke: #8b949e; }
  .node .label { fill: #f0f6fc; font: 12px monospace; font-weight: 700; }
  .node .meta { fill: #8b949e; font: 10px monospace; }
  .node title { font: 10px monospace; }
  .edge path { fill: none; stroke: #8b949e; stroke-width: 1.7; marker-end: url(#arrow-default); }
  .edge-tree path { stroke-width: 2.1; }
  .edge-cross path { opacity: .45; stroke-dasharray: 5 4; }
  .edge-read path, .edge-used path { stroke: #58a6ff; marker-end: url(#arrow-read); }
  .edge-write path, .edge-created path { stroke: #3fb950; marker-end: url(#arrow-write); }
  .edge-exec path, .edge-forked path { stroke: #d29922; marker-end: url(#arrow-exec); }
  .edge-network path { stroke: #f85149; marker-end: url(#arrow-network); }
  .edge-derived path { stroke: #a371f7; marker-end: url(#arrow-derived); }
  .edge-context path { stroke: #8b949e; marker-end: url(#arrow-context); stroke-dasharray: 4 3; }
  .edge text { fill: #f0f6fc; font: 10px monospace; text-anchor: middle; paint-order: stroke; stroke: #0d1117; stroke-width: 3px; }
  .edge-label-read { fill: #b6dcff; }
  .edge-label-write { fill: #b7f7c2; }
  .edge-label-exec { fill: #ffd58a; }
  .edge-label-network { fill: #ffb3ad; }
  .edge-label-derived { fill: #d8b9ff; }
  .title { fill: #f0f6fc; font: 16px sans-serif; font-weight: bold; }
  .subtitle { fill: #8b949e; font: 11px sans-serif; }
  .legend text { fill: #c9d1d9; font: 10px monospace; }
  .event-table text { fill: #c9d1d9; font: 11px monospace; }
  .event-table .header { fill: #58a6ff; font-weight: 700; }
  .event-table .group-title { fill: #f0f6fc; font-weight: 700; }
  .event-table .group-meta { fill: #8b949e; }
  .event-table rect { fill: #161b22; stroke: #30363d; rx: 8; }
  .event-row rect { fill: #0d1117; stroke: #21262d; rx: 6; }
  .event-group rect { fill: #10151d; stroke: #30363d; rx: 7; }
</style>
<defs>
  %s
</defs>
<rect class="bg" x="0" y="0" width="%d" height="%d"/>
<text x="18" y="22" class="title">ProvidAPT Provenance Trace</text>
<text x="18" y="40" class="subtitle">%s</text>
<text x="18" y="54" class="subtitle">Tree layout is left-to-right; Causal direction is rendered as source -&gt; target; dashed edges are retained cross-links; dashed boxes summarize folded same-layer nodes.</text>
`, lay.width, lay.height, lay.width, lay.height, svgMarkers(), lay.width, lay.height, escapeXML(scope))

	nodeMap := make(map[string]svgNode)
	for _, n := range lay.nodes {
		nodeMap[n.id] = n
	}
	for _, cluster := range lay.clusters {
		fmt.Fprintf(&b, `<g class="cluster cluster-%s">
  <title>%s</title>
  <rect x="%d" y="%d" width="%d" height="%d"/>
  <text class="label" x="%d" y="%d">%s</text>
  <text class="meta" x="%d" y="%d">%d folded node(s), depth=%d</text>
  <text class="meta" x="%d" y="%d">%s</text>
</g>
`, escapeXML(cluster.typ), escapeXML(clusterTitle(cluster)), cluster.x, cluster.y, cluster.w, cluster.h, cluster.x+10, cluster.y+22, escapeXML(cluster.title), cluster.x+10, cluster.y+40, cluster.count, cluster.depth, cluster.x+10, cluster.y+58, escapeXML(clusterMemberPreview(cluster)))
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
		x1 := src.x + src.w
		y1 := src.y + src.h/2
		x2 := dst.x
		y2 := dst.y + dst.h/2
		if dst.x <= src.x {
			x1 = src.x + src.w/2
			y1 = src.y + src.h
			x2 = dst.x + dst.w/2
			y2 = dst.y
		}
		midX := (x1 + x2) / 2
		labelY := (y1+y2)/2 - 6
		edgeClass := "edge-cross"
		if e.tree {
			edgeClass = "edge-tree"
		}
		fmt.Fprintf(&b, `<g class="edge %s edge-%s edge-%s" data-direction="%s-&gt;%s" data-tree="%t">
  <path d="%s"/>
  <text class="edge-label-%s" x="%d" y="%d">%s -&gt;</text>
</g>
`, edgeClass, e.rel, e.kind, escapeXML(e.src), escapeXML(e.dst), e.tree, edgePath(x1, y1, x2, y2), e.kind, midX+edgeLabelDX, labelY, escapeXML(e.event))
	}

	renderLegend(&b, lay.width)
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
  <title>%s</title>
  <rect x="%d" y="%d" width="%d" height="%d"/>
  %s
</g>
`, class, escapeXML(nodeTitle(n)), n.x, n.y, n.w, n.h, renderNodeText(n))
	}

	renderEventTable(&b, lay)
	b.WriteString("</svg>\n")
	return []byte(b.String())
}

func renderEventTable(b *strings.Builder, lay *svgLayout) {
	tableY := lay.graphH + 24
	groups := groupedSVGEvents(lay.edges)
	tableH := eventTableHeight(lay.edges)
	fmt.Fprintf(b, `<g class="event-table">
  <rect x="18" y="%d" width="%d" height="%d"/>
  <text class="header" x="34" y="%d">Event Structure (%d categories, %d visible edges, %d folded nodes)</text>
`, tableY, lay.width-36, tableH, tableY+24, len(groups), len(lay.edges), lay.collapsedNodes)
	if len(lay.edges) == 0 {
		fmt.Fprintf(b, `  <text x="34" y="%d">No edges are available for this trace.</text>
</g>
`, tableY+52)
		return
	}
	y := tableY + 42
	for _, group := range groups {
		visibleRows := minInt(len(group.edges), 3)
		groupH := 34
		for i := 0; i < visibleRows; i++ {
			groupH += eventRowHeight(group.edges[i])
		}
		if len(group.edges) > visibleRows {
			groupH += 18
		}
		fmt.Fprintf(b, `<g class="event-group">
  <rect x="30" y="%d" width="%d" height="%d"/>
  <text class="group-title" x="42" y="%d">%s</text>
  <text class="group-meta" x="280" y="%d">%d edge(s), %d cross-link(s)</text>
`, y, lay.width-60, groupH, y+18, escapeXML(group.title), y+18, len(group.edges), group.crossLinks)
		for i, e := range group.edges {
			if i >= visibleRows {
				break
			}
			rowY := y + 40
			for j := 0; j < i; j++ {
				rowY += eventRowHeight(group.edges[j])
			}
			summary := fmt.Sprintf("#%02d %-14s %s", i+1, e.event, e.summary)
			for lineIndex, line := range wrapText(summary, 132, 0) {
				fmt.Fprintf(b, `  <text x="52" y="%d">%s</text>
`, rowY+lineIndex*12, escapeXML(line))
			}
			detailStartY := rowY + len(wrapText(summary, 132, 0))*12
			for lineIndex, line := range wrapText(e.detail, 132, 0) {
				fmt.Fprintf(b, `  <text class="group-meta" x="52" y="%d">%s</text>
`, detailStartY+lineIndex*12, escapeXML(line))
			}
		}
		if len(group.edges) > visibleRows {
			fmt.Fprintf(b, `  <text class="group-meta" x="52" y="%d">%d more event relation(s) collapsed in this category</text>
`, y+groupH-12, len(group.edges)-visibleRows)
		}
		b.WriteString("</g>\n")
		y += groupH + 10
	}
	b.WriteString("</g>\n")
}

func eventTableHeight(edges []svgEdge) int {
	groups := groupedSVGEvents(edges)
	if len(groups) == 0 {
		return 110
	}
	height := 58
	for _, group := range groups {
		visibleRows := minInt(len(group.edges), 3)
		groupH := 34
		for i := 0; i < visibleRows; i++ {
			groupH += eventRowHeight(group.edges[i])
		}
		height += groupH + 10
		if len(group.edges) > visibleRows {
			height += 18
		}
	}
	return maxInt(150, height)
}

func eventRowHeight(edge svgEdge) int {
	summary := fmt.Sprintf("%-14s %s", edge.event, edge.summary)
	return 10 + len(wrapText(summary, 132, 0))*12 + len(wrapText(edge.detail, 132, 0))*12
}

func groupedSVGEvents(edges []svgEdge) []svgEventGroup {
	groupMap := map[string]*svgEventGroup{}
	for _, edge := range edges {
		key, title := svgEventCategory(edge)
		group, ok := groupMap[key]
		if !ok {
			group = &svgEventGroup{key: key, title: title}
			groupMap[key] = group
		}
		group.edges = append(group.edges, edge)
		if !edge.tree {
			group.crossLinks++
		}
	}
	order := []string{"execution", "file-read", "file-write", "network", "derived", "context", "other"}
	var groups []svgEventGroup
	for _, key := range order {
		if group, ok := groupMap[key]; ok {
			groups = append(groups, *group)
			delete(groupMap, key)
		}
	}
	var rest []string
	for key := range groupMap {
		rest = append(rest, key)
	}
	sort.Strings(rest)
	for _, key := range rest {
		groups = append(groups, *groupMap[key])
	}
	return groups
}

func svgEventCategory(edge svgEdge) (string, string) {
	event := strings.ToLower(edge.event + " " + edge.rel + " " + edge.kind)
	switch {
	case strings.Contains(event, "exec") || strings.Contains(event, "fork") || edge.kind == "exec":
		return "execution", "Execution / Process Activity"
	case strings.Contains(event, "connect") || strings.Contains(event, "network") || edge.kind == "network":
		return "network", "Command and Control / Network"
	case strings.Contains(event, "write") || strings.Contains(event, "create") || edge.kind == "write":
		return "file-write", "Persistence or Collection / File Writes"
	case strings.Contains(event, "read") || strings.Contains(event, "open") || edge.kind == "read":
		return "file-read", "Discovery or Credential Access / File Reads"
	case edge.kind == "derived":
		return "derived", "Data Derivation"
	case edge.kind == "context":
		return "context", "Security Context"
	default:
		return "other", "Other Provenance Relations"
	}
}

func renderLegend(b *strings.Builder, width int) {
	items := []struct {
		label string
		color string
	}{
		{"read/use", "#58a6ff"},
		{"write/create", "#3fb950"},
		{"exec/fork", "#d29922"},
		{"network", "#f85149"},
		{"derived", "#a371f7"},
		{"folded", "#6e7681"},
	}
	x := maxInt(360, width-510)
	fmt.Fprintf(b, `<g class="legend" transform="translate(%d,16)">`, x)
	for i, item := range items {
		offset := i * 78
		fmt.Fprintf(b, `<line x1="%d" y1="0" x2="%d" y2="0" stroke="%s" stroke-width="2"/>
<text x="%d" y="4">%s</text>`, offset, offset+18, item.color, offset+23, escapeXML(item.label))
	}
	b.WriteString("</g>\n")
}

func svgMarkers() string {
	markers := []struct {
		id    string
		color string
	}{
		{"default", "#8b949e"},
		{"read", "#58a6ff"},
		{"write", "#3fb950"},
		{"exec", "#d29922"},
		{"network", "#f85149"},
		{"derived", "#a371f7"},
		{"context", "#8b949e"},
	}
	var b strings.Builder
	for _, marker := range markers {
		fmt.Fprintf(&b, `<marker id="arrow-%s" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto">
    <path d="M0,0 L10,5 L0,10 Z" fill="%s"/>
  </marker>
  `, marker.id, marker.color)
	}
	return b.String()
}

func makeSVGNode(n *provenance.Node, _ int) svgNode {
	node := svgNode{
		id:      n.ID,
		label:   n.Label,
		detail1: nodeDetailLine(n),
		detail2: nodeIdentityLine(n),
		typ:     n.Subtype,
	}
	node.w = measureNodeWidth(node)
	lineCount := len(nodeTextLines(node))
	node.h = maxInt(minNodeH, 18+lineCount*13+10)
	return node
}

func displayType(typ string) string {
	switch strings.TrimSpace(typ) {
	case "process":
		return "Process"
	case "file":
		return "File"
	case "network":
		return "Network"
	case "credential":
		return "Credential"
	case "":
		return "Node"
	default:
		return strings.Title(typ)
	}
}

func clusterTitle(cluster svgCluster) string {
	return fmt.Sprintf("%s: %s", cluster.title, strings.Join(cluster.members, ", "))
}

func clusterMemberPreview(cluster svgCluster) string {
	if len(cluster.members) == 0 {
		return "No folded members"
	}
	limit := minInt(3, len(cluster.members))
	preview := strings.Join(cluster.members[:limit], ", ")
	if len(cluster.members) > limit {
		preview += fmt.Sprintf(", +%d more", len(cluster.members)-limit)
	}
	return preview
}

func measureNodeWidth(n svgNode) int {
	longest := maxInt(16, longestDisplayLen(n.label))
	longest = maxInt(longest, longestDisplayLen(n.detail1))
	longest = maxInt(longest, longestDisplayLen(n.detail2))
	return clampInt(longest*7+24, minNodeW, maxNodeW)
}

func nodeTextLines(n svgNode) []struct {
	class string
	text  string
} {
	widthChars := maxInt(24, (n.w-20)/7)
	raw := []struct {
		class string
		text  string
	}{
		{"label", n.label},
		{"meta", n.detail1},
		{"meta", n.detail2},
	}
	var out []struct {
		class string
		text  string
	}
	for _, group := range raw {
		for _, line := range wrapText(group.text, widthChars, 0) {
			out = append(out, struct {
				class string
				text  string
			}{class: group.class, text: line})
		}
	}
	return out
}

func renderNodeText(n svgNode) string {
	var b strings.Builder
	y := n.y + 20
	for _, line := range nodeTextLines(n) {
		fmt.Fprintf(&b, `<text class="%s" x="%d" y="%d">%s</text>
  `, line.class, n.x+10, y, escapeXML(line.text))
		y += 13
	}
	return b.String()
}

func wrapText(text string, width, maxLines int) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	var lines []string
	for len(text) > width && (maxLines <= 0 || len(lines) < maxLines-1) {
		cut := width
		if idx := strings.LastIndexAny(text[:width], "/ :-_=."); idx > 10 {
			cut = idx + 1
		}
		lines = append(lines, strings.TrimSpace(text[:cut]))
		text = strings.TrimSpace(text[cut:])
	}
	if text != "" {
		lines = append(lines, text)
	}
	return lines
}

func edgePath(x1, y1, x2, y2 int) string {
	if x2 > x1 {
		midX := (x1 + x2) / 2
		return fmt.Sprintf("M%d,%d C%d,%d %d,%d %d,%d", x1, y1, midX, y1, midX, y2, x2, y2)
	}
	arc := maxInt(60, absInt(y2-y1)/2+30)
	return fmt.Sprintf("M%d,%d C%d,%d %d,%d %d,%d", x1, y1, x1, y1+arc, x2, y2-arc, x2, y2)
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

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clampInt(v, min, max int) int {
	return minInt(maxInt(v, min), max)
}

func longestDisplayLen(text string) int {
	longest := 0
	for _, part := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '/' || r == ':' || r == '=' || r == ',' || r == ';'
	}) {
		longest = maxInt(longest, len(part))
	}
	return maxInt(longest, len(text)/2)
}

func nodeDetailLine(n *provenance.Node) string {
	switch n.Subtype {
	case "process":
		return compactJoin([]string{kv("pid", n.Attributes["pid"]), kv("ppid", n.Attributes["ppid"]), kv("uid", n.Attributes["uid"]), kv("comm", n.Attributes["comm"])})
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
		return firstAttr(n.Attributes, []string{"cmdline", "exe_path"}, n.ID)
	case "file":
		return stringAttr(n.Attributes, "pathname", n.ID)
	default:
		return n.ID
	}
}

func nodeTitle(n svgNode) string {
	return compactJoin([]string{n.id, n.label, n.detail1, n.detail2})
}

func edgeSummary(e *provenance.Edge) string {
	return fmt.Sprintf("%s -> %s (%s)", e.Source, e.Target, shortRel(e.Relation))
}

func edgeDetail(e *provenance.Edge) string {
	keys := []string{"pid", "comm", "cmdline", "path", "inode", "f_flags", "child_pid", "prev"}
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
	return compactJoin(parts)
}

func edgeKind(e *provenance.Edge) string {
	event := strings.ToLower(stringAttr(e.Attributes, "event", ""))
	rel := shortRel(e.Relation)
	switch {
	case strings.Contains(event, "connect") || strings.Contains(event, "network"):
		return "network"
	case strings.Contains(event, "exec") || strings.Contains(event, "fork") || rel == "forked":
		return "exec"
	case strings.Contains(event, "write") || strings.Contains(event, "create") || rel == "created":
		return "write"
	case strings.Contains(event, "read") || strings.Contains(event, "open") || rel == "used":
		return "read"
	case rel == "derived":
		return "derived"
	case rel == "context":
		return "context"
	default:
		return "default"
	}
}

func firstAttr(attrs map[string]interface{}, keys []string, fallback string) string {
	for _, key := range keys {
		if value := stringAttr(attrs, key, ""); value != "" {
			return value
		}
	}
	return fallback
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
