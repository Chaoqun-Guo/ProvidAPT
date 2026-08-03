// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/url"
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
	layoutMode     string
	truncate       bool
	collapsedNodes int
}

type svgNode struct {
	id      string
	label   string
	detail1 string
	detail2 string
	typ     string
	depth   int
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
	reason  string
}

const (
	minNodeW    = 240
	maxNodeW    = 520
	minNodeH    = 82
	xPad        = 36
	yPad        = 42
	layerGap    = 120
	topY        = 120
	minGraphH   = 320
	edgeLabelDX = 10
	clusterMin  = 5
	clusterKeep = 3
)

func generateAlertSVG(alertID string, graph *provenance.Graph) []byte {
	return generateAlertSVGWithLayout(alertID, graph, "tree")
}

func generateAlertSVGWithLayout(alertID string, graph *provenance.Graph, mode string) []byte {
	nodes, edges, truncated := focusedGraph(alertID, graph, 4, 80, 120)
	if len(nodes) == 0 {
		return defaultSVG("No provenance events are available yet")
	}
	layout := layoutGraph(nodes, edges)
	applyServerSVGLayout(layout, normalizeSVGLayoutMode(mode))
	layout.scope = alertID
	layout.truncate = truncated
	return renderSVG(layout)
}

func renderTraceSVGViewer(alertID string) []byte {
	encodedID := url.PathEscape(alertID)
	rawPath := "/api/v1/alerts/" + encodedID + "/svg"
	reportPath := "/api/v1/investigation/report?node=" + url.QueryEscape(alertID) + "&direction=backward&depth=5"
	reportMarkdownPath := reportPath + "&format=markdown"
	var b strings.Builder
	fmt.Fprintf(&b, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ProvidAPT Trace Viewer - %s</title>
<style>
:root {
  color-scheme: dark;
  --bg: #07101f;
  --panel: rgba(9, 20, 37, 0.92);
  --panel-strong: rgba(13, 28, 52, 0.98);
  --line: rgba(88, 166, 255, 0.24);
  --text: #d7e8ff;
  --muted: #8b949e;
  --cyan: #00e5ff;
  --green: #19f28a;
  --amber: #ffb020;
  --red: #ff3158;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at 14%% 10%%, rgba(0, 229, 255, 0.12), transparent 32%%),
    linear-gradient(135deg, #06101f 0%%, #0a1324 54%%, #101827 100%%);
  color: var(--text);
  font-family: Inter, "Segoe UI", Arial, sans-serif;
  overflow: hidden;
}
.trace-shell { display: grid; grid-template-rows: auto 1fr; height: 100vh; }
.trace-header {
  display: grid;
  grid-template-columns: minmax(220px, 1fr) auto;
  gap: 12px;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--line);
  background: rgba(2, 8, 18, 0.88);
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.28);
}
.brand { display: grid; gap: 2px; min-width: 0; }
.title { font-size: 16px; font-weight: 850; letter-spacing: 0.4px; }
.scope { color: var(--muted); font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.toolbar { display: flex; gap: 7px; flex-wrap: wrap; justify-content: flex-end; align-items: center; }
button, a.tool-link {
  height: 30px;
  min-width: 96px;
  padding: 0 12px;
  border-radius: 999px;
  border: 1px solid rgba(88, 166, 255, 0.36);
  background: linear-gradient(180deg, rgba(17, 34, 58, 0.96), rgba(8, 18, 33, 0.96));
  color: var(--text);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  font-size: 11px;
  font-weight: 760;
  text-decoration: none;
  cursor: pointer;
}
button:hover, a.tool-link:hover { border-color: var(--cyan); box-shadow: 0 0 18px rgba(0, 229, 255, 0.18); }
button.mode-active { border-color: var(--green); color: #d8ffed; box-shadow: inset 0 0 0 1px rgba(25, 242, 138, 0.22); }
.search {
  height: 30px;
  width: 210px;
  border-radius: 999px;
  border: 1px solid rgba(88, 166, 255, 0.24);
  background: rgba(3, 8, 18, 0.7);
  color: var(--text);
  padding: 0 12px;
  outline: none;
}
.viewer {
  display: grid;
  grid-template-columns: 1fr 280px;
  gap: 10px;
  padding: 10px;
  height: 100%%;
  min-height: 0;
}
.canvas-wrap {
  min-width: 0;
  min-height: 0;
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: 16px;
  background: rgba(3, 8, 18, 0.74);
  box-shadow: inset 0 0 0 1px rgba(0, 229, 255, 0.035), 0 18px 48px rgba(0, 0, 0, 0.28);
}
.canvas {
  transform-origin: 0 0;
  transition: transform 0.12s ease;
  min-width: max-content;
  min-height: max-content;
}
.fallback-frame {
  width: 100%%;
  min-height: 72vh;
  border: 0;
  background: #0d1117;
  border-radius: 12px;
}
.canvas svg {
  max-width: none !important;
  height: auto !important;
  margin: 0 !important;
}
.side {
  min-width: 0;
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: 16px;
  background: var(--panel);
  padding: 10px;
  display: grid;
  align-content: start;
  gap: 10px;
}
.card {
  border: 1px solid rgba(88, 166, 255, 0.16);
  border-radius: 12px;
  background: rgba(3, 8, 18, 0.36);
  padding: 10px;
}
.card h2 {
  margin: 0 0 8px;
  color: #f0f6fc;
  font-size: 12px;
  letter-spacing: 0.8px;
  text-transform: uppercase;
}
.metric-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
.metric { border-radius: 10px; background: rgba(7, 16, 30, 0.86); padding: 8px; }
.metric .value { color: var(--cyan); font-weight: 850; font-size: 17px; }
.metric .label { color: var(--muted); font-size: 9px; text-transform: uppercase; letter-spacing: 0.7px; }
.legend { display: grid; gap: 6px; font-size: 11px; color: var(--muted); }
.legend span::before { content: ""; display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 6px; vertical-align: -1px; }
.process::before { background: #58a6ff; }
.file::before { background: #3fb950; }
.network::before { background: #f85149; }
.credential::before { background: #d29922; }
.read::before { background: #58a6ff; }
.write::before { background: #3fb950; }
.exec::before { background: #d29922; }
.context::before { background: #8b949e; }
.status { color: var(--muted); font-size: 11px; line-height: 1.45; }
.detail-panel { display: grid; gap: 8px; }
.detail-empty { color: var(--muted); font-size: 11px; line-height: 1.45; }
.detail-title { color: #f0f6fc; font-size: 12px; font-weight: 800; overflow-wrap: anywhere; }
.detail-table { display: grid; gap: 5px; }
.detail-row { display: grid; grid-template-columns: 76px minmax(0, 1fr); gap: 8px; align-items: start; }
.detail-key { color: var(--muted); font-size: 9px; font-weight: 800; letter-spacing: 0.7px; text-transform: uppercase; }
.detail-value { color: var(--text); font-size: 11px; line-height: 1.35; overflow-wrap: anywhere; white-space: pre-wrap; }
.export-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 7px; }
.export-grid button { min-width: 0; width: 100%%; }
.error { color: #ffd7df; border-color: rgba(255, 49, 88, 0.36); }
.dimmed { opacity: 0.16; }
.filtered-hidden { display: none; }
.matched rect { stroke: var(--cyan) !important; stroke-width: 3 !important; filter: drop-shadow(0 0 8px rgba(0, 229, 255, 0.55)); }
.selected rect, .selected path { stroke: var(--cyan) !important; stroke-width: 3 !important; filter: drop-shadow(0 0 9px rgba(0, 229, 255, 0.58)); }
.node, .edge, .cluster { cursor: pointer; }
.hide-cross .edge-cross { display: none; }
.cluster-highlight .cluster rect { stroke: var(--amber) !important; stroke-width: 3 !important; filter: drop-shadow(0 0 10px rgba(255, 176, 32, 0.55)); }
@media (max-width: 980px) {
  body { overflow: auto; }
  .trace-shell { height: auto; min-height: 100vh; }
  .trace-header, .viewer { grid-template-columns: 1fr; }
  .toolbar { justify-content: flex-start; }
  .search { width: 100%%; }
  .viewer { height: auto; }
  .canvas-wrap { min-height: 60vh; }
}
</style>
</head>
<body>
<div class="trace-shell">
  <header class="trace-header">
    <div class="brand">
      <div class="title">ProvidAPT Trace Viewer</div>
      <div class="scope">Focused alert: %s</div>
    </div>
    <div class="toolbar">
      <input class="search" id="searchBox" placeholder="Search node, event, path, cmdline">
      <select class="tool-link" id="typeFilter" onchange="setTypeFilter(this.value)" aria-label="Filter trace by node type">
        <option value="all">All Types</option>
        <option value="process">Processes</option>
        <option value="file">Files</option>
        <option value="network">Network</option>
        <option value="credential">Credentials</option>
      </select>
      <button onclick="zoomBy(0.12)">Zoom In</button>
      <button onclick="zoomBy(-0.12)">Zoom Out</button>
      <button onclick="fitWidth()">Fit Width</button>
      <button data-layout-mode="tree" class="mode-active" onclick="applyLayoutMode('tree')">Tree</button>
      <button data-layout-mode="compact" onclick="applyLayoutMode('compact')">Compact</button>
      <button data-layout-mode="timeline" onclick="applyLayoutMode('timeline')">Timeline</button>
      <button data-layout-mode="grouped" onclick="applyLayoutMode('grouped')">Grouped</button>
      <button data-collapse-type="file" onclick="toggleTypeCollapse('file')">Fold Files</button>
      <button data-collapse-type="network" onclick="toggleTypeCollapse('network')">Fold Network</button>
      <button onclick="focusSelectedPath()">Path Only</button>
      <button onclick="expandTrace()">Expand All</button>
      <button onclick="toggleCrossLinks()">Cross Links</button>
      <button onclick="toggleClusters()">Clusters</button>
      <button onclick="exportPNG()">PNG</button>
      <button onclick="copyReportSnippet()">Report</button>
      <a class="tool-link" href="%s" target="_blank" rel="noreferrer">Raw SVG</a>
      <a class="tool-link" href="%s" download="providapt-trace.svg">SVG</a>
      <a class="tool-link" href="%s" target="_blank" rel="noreferrer">MD Report</a>
      <a class="tool-link" href="%s" target="_blank" rel="noreferrer">JSON</a>
    </div>
  </header>
  <main class="viewer">
    <section class="canvas-wrap" id="canvasWrap" aria-label="Trace SVG canvas">
      <div class="canvas" id="canvas"><div class="card status">Loading trace SVG...</div></div>
    </section>
    <aside class="side" aria-label="Trace analysis summary">
      <div class="card">
        <h2>Trace Summary</h2>
        <div class="metric-grid">
          <div class="metric"><div class="value" id="nodeCount">--</div><div class="label">Nodes</div></div>
          <div class="metric"><div class="value" id="edgeCount">--</div><div class="label">Edges</div></div>
          <div class="metric"><div class="value" id="crossCount">--</div><div class="label">Cross Links</div></div>
          <div class="metric"><div class="value" id="clusterCount">--</div><div class="label">Clusters</div></div>
        </div>
      </div>
      <div class="card">
        <h2>Legend</h2>
        <div class="legend">
          <span class="process">Process node</span>
          <span class="file">File node</span>
          <span class="network">Network node</span>
          <span class="credential">Credential node</span>
          <span class="read">Read / use relation</span>
          <span class="write">Write / create relation</span>
          <span class="exec">Execution relation</span>
          <span class="context">Dashed context or cross-link</span>
          <span class="credential">Folded cluster: same layer/type nodes summarized for readability</span>
        </div>
      </div>
      <div class="card detail-panel">
        <h2>Selected Element</h2>
        <div id="detailPanel" class="detail-empty">Select a node, edge, or folded cluster in the trace.</div>
      </div>
      <div class="card">
        <h2>Export</h2>
        <div class="export-grid">
          <button onclick="downloadInlineSVG()">SVG</button>
          <button onclick="exportPNG()">PNG</button>
          <button onclick="copyReportSnippet()">Report</button>
          <button onclick="copySelectedDetail()">Detail</button>
        </div>
      </div>
      <div class="card status" id="viewerStatus">
        Direction is source -> target. Use search to isolate a path, command line, file path, event type, or process node.
      </div>
    </aside>
  </main>
</div>
<script>
const rawURL = %q;
const alertID = %q;
const API_KEY_STORAGE = 'providapt_api_key';
const API_KEY_REMEMBER_STORAGE = 'providapt_api_key_remember';
let apiKey = sessionStorage.getItem(API_KEY_STORAGE) || localStorage.getItem(API_KEY_STORAGE) || '';
let scale = 1;
const canvas = document.getElementById('canvas');
const wrap = document.getElementById('canvasWrap');
const layoutState = { mode: 'tree', typeFilter: 'all', collapsedTypes: new Set(), searchQuery: '', pathFocus: new Set() };

fetch(rawURL, { cache: 'no-store', headers: authHeaders() })
  .then(response => {
    if (!response.ok) throw new Error('HTTP ' + response.status);
    return response.text();
  })
  .then(svg => {
    canvas.innerHTML = svg;
    summarizeTrace();
    bindTraceDetails();
    fitWidth();
  })
  .catch(error => {
    showFallback('Unable to inline trace SVG: ' + error.message + '. Raw SVG is embedded below.');
  });

function authHeaders() {
  return apiKey ? { 'X-API-Key': apiKey } : {};
}
function updateAuthNotice(message) {
  const status = document.getElementById('viewerStatus');
  if (status) status.textContent = message;
}
window.setTimeout(() => {
  if (!canvas.querySelector('svg') && !canvas.querySelector('iframe')) {
    showFallback('Trace SVG is still loading. Raw SVG is embedded below as a fallback.');
  }
}, 1800);

function summarizeTrace() {
  setMetric('nodeCount', canvas.querySelectorAll('.node').length);
  setMetric('edgeCount', canvas.querySelectorAll('.edge').length);
  setMetric('crossCount', canvas.querySelectorAll('.edge-cross').length);
  setMetric('clusterCount', canvas.querySelectorAll('.cluster').length);
}
function initLayoutState() {
  Array.from(canvas.querySelectorAll('.node')).forEach(node => {
    const rect = node.querySelector('rect');
    if (!rect) return;
    node.dataset.originX = String(Number(rect.getAttribute('x')) || 0);
    node.dataset.originY = String(Number(rect.getAttribute('y')) || 0);
    node.dataset.width = String(Number(rect.getAttribute('width')) || 0);
    node.dataset.height = String(Number(rect.getAttribute('height')) || 0);
    node.dataset.currentX = node.dataset.originX;
    node.dataset.currentY = node.dataset.originY;
  });
  const table = canvas.querySelector('.event-table');
  const tableRect = table ? table.querySelector('rect') : null;
  if (tableRect) {
    table.dataset.originY = String(Number(tableRect.getAttribute('y')) || 0);
    table.dataset.height = String(Number(tableRect.getAttribute('height')) || 0);
  }
}
function applyLayoutMode(mode) {
  const svg = currentSVG();
  if (!svg) return;
  initLayoutState();
  layoutState.mode = mode;
  updateLayoutButtons(mode);
  const nodes = Array.from(canvas.querySelectorAll('.node'));
  const groups = {};
  nodes.forEach(node => {
    const key = mode === 'grouped' ? (node.dataset.nodeType || 'node') : (node.dataset.depth || '0');
    if (!groups[key]) groups[key] = [];
    groups[key].push(node);
  });
  const typeOrder = ['process', 'file', 'network', 'credential', 'node'];
  const keys = Object.keys(groups).sort((a, b) => {
    if (mode === 'grouped') {
      const ai = typeOrder.indexOf(a);
      const bi = typeOrder.indexOf(b);
      return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi) || a.localeCompare(b);
    }
    return Number(a) - Number(b);
  });
  const next = new Map();
  if (mode === 'tree') {
    nodes.forEach(node => next.set(node, { x: Number(node.dataset.originX), y: Number(node.dataset.originY) }));
  } else if (mode === 'compact') {
    keys.forEach((key, col) => {
      groups[key].forEach((node, row) => next.set(node, { x: 36 + col * 300, y: 96 + row * 78 }));
    });
  } else if (mode === 'timeline') {
    const ordered = nodes.slice().sort((a, b) => Number(a.dataset.originX) - Number(b.dataset.originX) || Number(a.dataset.originY) - Number(b.dataset.originY));
    ordered.forEach((node, row) => next.set(node, { x: 96 + Number(node.dataset.depth || 0) * 28, y: 96 + row * 88 }));
  } else {
    keys.forEach((key, col) => {
      groups[key].forEach((node, row) => next.set(node, { x: 36 + col * 320, y: 96 + row * 86 }));
    });
  }
  let maxX = 0;
  let maxY = 0;
  next.forEach((pos, node) => {
    const dx = pos.x - Number(node.dataset.originX);
    const dy = pos.y - Number(node.dataset.originY);
    node.setAttribute('transform', dx || dy ? 'translate(' + dx + ' ' + dy + ')' : '');
    node.dataset.currentX = String(pos.x);
    node.dataset.currentY = String(pos.y);
    maxX = Math.max(maxX, pos.x + Number(node.dataset.width));
    maxY = Math.max(maxY, pos.y + Number(node.dataset.height));
  });
  rerouteEdges();
  repositionEventTable(maxY + 60);
  const table = canvas.querySelector('.event-table');
  const tableBottom = table ? Number(table.dataset.currentY || table.dataset.originY || 0) + Number(table.dataset.height || 0) : maxY;
  const width = Math.max(Number(svg.getAttribute('width')) || 0, maxX + 80);
  const height = Math.max(tableBottom + 40, maxY + 120);
  svg.setAttribute('width', String(Math.ceil(width)));
  svg.setAttribute('height', String(Math.ceil(height)));
  svg.setAttribute('viewBox', '0 0 ' + Math.ceil(width) + ' ' + Math.ceil(height));
  document.getElementById('viewerStatus').textContent = 'Layout mode: ' + mode + '. Edge paths were recalculated in the viewer.';
  fitWidth();
}
function updateLayoutButtons(mode) {
  document.querySelectorAll('[data-layout-mode]').forEach(button => {
    button.classList.toggle('mode-active', button.dataset.layoutMode === mode);
  });
}
function rerouteEdges() {
  const nodeByID = new Map();
  Array.from(canvas.querySelectorAll('.node')).forEach(node => nodeByID.set(node.dataset.nodeId, node));
  Array.from(canvas.querySelectorAll('.edge')).forEach(edge => {
    const src = nodeByID.get(edge.dataset.source);
    const dst = nodeByID.get(edge.dataset.target);
    if (!src || !dst) return;
    const a = nodeBox(src);
    const b = nodeBox(dst);
    let x1 = a.x + a.w;
    let y1 = a.y + a.h / 2;
    let x2 = b.x;
    let y2 = b.y + b.h / 2;
    if (b.x <= a.x) {
      x1 = a.x + a.w / 2;
      y1 = a.y + a.h;
      x2 = b.x + b.w / 2;
      y2 = b.y;
    }
    const midX = (x1 + x2) / 2;
    const labelY = (y1 + y2) / 2 - 6;
    const path = edge.querySelector('path');
    const label = edge.querySelector('text');
    if (path) path.setAttribute('d', svgEdgePath(x1, y1, x2, y2));
    if (label) {
      label.setAttribute('x', String(Math.round(midX + 10)));
      label.setAttribute('y', String(Math.round(labelY)));
    }
  });
}
function nodeBox(node) {
  return {
    x: Number(node.dataset.currentX || node.dataset.originX || 0),
    y: Number(node.dataset.currentY || node.dataset.originY || 0),
    w: Number(node.dataset.width || 0),
    h: Number(node.dataset.height || 0)
  };
}
function svgEdgePath(x1, y1, x2, y2) {
  x1 = Math.round(x1); y1 = Math.round(y1); x2 = Math.round(x2); y2 = Math.round(y2);
  if (x2 > x1) {
    const midX = Math.round((x1 + x2) / 2);
    return 'M' + x1 + ',' + y1 + ' C' + midX + ',' + y1 + ' ' + midX + ',' + y2 + ' ' + x2 + ',' + y2;
  }
  const arc = Math.max(60, Math.round(Math.abs(y2 - y1) / 2 + 30));
  return 'M' + x1 + ',' + y1 + ' C' + x1 + ',' + (y1 + arc) + ' ' + x2 + ',' + (y2 - arc) + ' ' + x2 + ',' + y2;
}
function repositionEventTable(targetY) {
  const table = canvas.querySelector('.event-table');
  if (!table || !table.dataset.originY) return;
  const originY = Number(table.dataset.originY);
  const nextY = Math.max(originY, targetY);
  const dy = nextY - originY;
  table.setAttribute('transform', dy ? 'translate(0 ' + Math.round(dy) + ')' : '');
  table.dataset.currentY = String(nextY);
}
function bindTraceDetails() {
  const items = Array.from(canvas.querySelectorAll('.node, .edge, .cluster'));
  items.forEach(item => {
    item.setAttribute('tabindex', '0');
    item.setAttribute('role', 'button');
    item.addEventListener('click', event => {
      event.stopPropagation();
      selectTraceElement(item);
    });
    item.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        selectTraceElement(item);
      }
    });
  });
  const svg = canvas.querySelector('svg');
  if (svg) {
    svg.addEventListener('click', () => clearTraceSelection());
  }
}
function selectTraceElement(item) {
  canvas.querySelectorAll('.selected').forEach(selected => selected.classList.remove('selected'));
  item.classList.add('selected');
  const detail = traceElementDetail(item);
  document.getElementById('detailPanel').innerHTML = renderDetail(detail);
  document.getElementById('viewerStatus').textContent = detail.status;
}
function clearTraceSelection() {
  canvas.querySelectorAll('.selected').forEach(selected => selected.classList.remove('selected'));
  document.getElementById('detailPanel').innerHTML = 'Select a node, edge, or folded cluster in the trace.';
  document.getElementById('detailPanel').className = 'detail-empty';
}
function traceElementDetail(item) {
  if (item.classList.contains('node')) {
    return {
      title: item.dataset.nodeLabel || item.dataset.nodeId || 'Node',
      status: 'Node selected: ' + (item.dataset.nodeId || 'unknown'),
      rows: [
        ['ID', item.dataset.nodeId],
        ['Type', item.dataset.nodeType],
        ['Label', item.dataset.nodeLabel],
        ['Summary', item.dataset.detail],
        ['Identity', item.dataset.identity]
      ]
    };
  }
  if (item.classList.contains('edge')) {
    return {
      title: (item.dataset.event || item.dataset.relation || 'Edge') + ' relation',
      status: 'Edge selected: ' + (item.dataset.source || '?') + ' -> ' + (item.dataset.target || '?'),
      rows: [
        ['Source', item.dataset.source],
        ['Target', item.dataset.target],
        ['Relation', item.dataset.relation],
        ['Event', item.dataset.event],
        ['Kind', item.dataset.kind],
        ['Tree', item.dataset.tree],
        ['Summary', item.dataset.summary],
        ['Details', item.dataset.detail]
      ]
    };
  }
  return {
    title: item.dataset.clusterId || 'Folded cluster',
    status: 'Cluster selected: ' + (item.dataset.foldedCount || '0') + ' folded node(s)',
    rows: [
      ['Type', item.dataset.nodeType],
      ['Depth', item.dataset.depth],
      ['Folded', item.dataset.foldedCount],
      ['Reason', item.dataset.reason],
      ['Members', item.dataset.members]
    ]
  };
}
function renderDetail(detail) {
  document.getElementById('detailPanel').className = 'detail-panel';
  const rows = detail.rows
    .filter(row => row[1] !== undefined && row[1] !== null && String(row[1]).trim() !== '')
    .map(row => '<div class="detail-row"><div class="detail-key">' + escapeHTML(row[0]) + '</div><div class="detail-value">' + escapeHTML(row[1]) + '</div></div>')
    .join('');
  return '<div class="detail-title">' + escapeHTML(detail.title) + '</div><div class="detail-table">' + rows + '</div>';
}
function showFallback(message) {
  document.getElementById('viewerStatus').textContent = message;
  canvas.innerHTML = '<div class="card status">Loading authenticated raw SVG fallback...</div>';
  setMetric('nodeCount', '--');
  setMetric('edgeCount', '--');
  setMetric('crossCount', '--');
  setMetric('clusterCount', '--');
  document.getElementById('detailPanel').className = 'detail-empty';
  document.getElementById('detailPanel').textContent = 'Trace details are unavailable while the raw SVG fallback is active.';
  scale = 1;
  applyScale();
  fetch(rawURL, { cache: 'no-store', headers: authHeaders() })
    .then(response => {
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return response.text();
    })
    .then(svg => {
      const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml;charset=utf-8' }));
      canvas.innerHTML = '<iframe class="fallback-frame" src="' + url.replace(/"/g, '&quot;') + '" title="Raw trace SVG fallback"></iframe>';
      window.setTimeout(() => URL.revokeObjectURL(url), 60000);
    })
    .catch(error => {
      const hint = error.message.indexOf('401') >= 0 || error.message.indexOf('403') >= 0
        ? 'Trace SVG requires the same API key saved in the Dashboard.'
        : 'Raw SVG fallback failed: ' + error.message + '.';
      canvas.innerHTML = '<div class="card status error">' + escapeHTML(hint) + '</div>';
      updateAuthNotice(hint);
    });
}
function setMetric(id, value) { document.getElementById(id).textContent = String(value); }
function setTypeFilter(type) {
  layoutState.typeFilter = type || 'all';
  applyTraceVisibility();
}
function toggleTypeCollapse(type) {
  if (layoutState.collapsedTypes.has(type)) {
    layoutState.collapsedTypes.delete(type);
  } else {
    layoutState.collapsedTypes.add(type);
  }
  updateCollapseButtons();
  applyTraceVisibility();
}
function expandTrace() {
  layoutState.typeFilter = 'all';
  layoutState.collapsedTypes.clear();
  layoutState.pathFocus.clear();
  const filter = document.getElementById('typeFilter');
  if (filter) filter.value = 'all';
  updateCollapseButtons();
  applyTraceVisibility();
}
function updateCollapseButtons() {
  document.querySelectorAll('[data-collapse-type]').forEach(button => {
    const active = layoutState.collapsedTypes.has(button.dataset.collapseType);
    button.classList.toggle('mode-active', active);
    button.textContent = active
      ? 'Show ' + labelForType(button.dataset.collapseType)
      : 'Fold ' + labelForType(button.dataset.collapseType);
  });
}
function labelForType(type) {
  return type === 'network' ? 'Network' : type.charAt(0).toUpperCase() + type.slice(1) + 's';
}
function applyTraceVisibility() {
  const nodes = Array.from(canvas.querySelectorAll('.node'));
  const clusters = Array.from(canvas.querySelectorAll('.cluster'));
  const hiddenNodeIDs = new Set();
  let visibleNodes = 0;
  let hiddenNodes = 0;
  nodes.forEach(node => {
    const type = node.dataset.nodeType || 'node';
    const text = nodeTraceText(node);
    const typeHidden = layoutState.typeFilter !== 'all' && type !== layoutState.typeFilter;
    const collapsed = layoutState.collapsedTypes.has(type);
    const searchHidden = layoutState.searchQuery && !text.includes(layoutState.searchQuery);
    const pathHidden = layoutState.pathFocus.size && !layoutState.pathFocus.has(node.dataset.nodeId);
    const hidden = typeHidden || collapsed || searchHidden || pathHidden;
    node.classList.toggle('filtered-hidden', hidden);
    if (hidden) {
      hiddenNodes++;
      if (node.dataset.nodeId) hiddenNodeIDs.add(node.dataset.nodeId);
    } else {
      visibleNodes++;
    }
  });
  clusters.forEach(cluster => {
    const type = cluster.dataset.nodeType || 'node';
    const typeHidden = layoutState.typeFilter !== 'all' && type !== layoutState.typeFilter;
    const searchHidden = layoutState.searchQuery && !nodeTraceText(cluster).includes(layoutState.searchQuery);
    cluster.classList.toggle('filtered-hidden', typeHidden || searchHidden || layoutState.pathFocus.size > 0);
  });
  let visibleEdges = 0;
  Array.from(canvas.querySelectorAll('.edge')).forEach(edge => {
    const text = nodeTraceText(edge);
    const endpointHidden = hiddenNodeIDs.has(edge.dataset.source) || hiddenNodeIDs.has(edge.dataset.target);
    const searchHidden = layoutState.searchQuery && !text.includes(layoutState.searchQuery);
    const pathHidden = layoutState.pathFocus.size && (!layoutState.pathFocus.has(edge.dataset.source) || !layoutState.pathFocus.has(edge.dataset.target));
    const hidden = endpointHidden || searchHidden || pathHidden;
    edge.classList.toggle('filtered-hidden', hidden);
    if (!hidden) visibleEdges++;
  });
  document.getElementById('viewerStatus').textContent =
    'Visible trace: ' + visibleNodes + ' node(s), ' + visibleEdges + ' edge(s), ' + hiddenNodes + ' folded/filtered node(s).';
}
function focusSelectedPath() {
  const selected = canvas.querySelector('.node.selected');
  if (!selected || !selected.dataset.nodeId) {
    document.getElementById('viewerStatus').textContent = 'Select a node before enabling path-only view.';
    return;
  }
  const start = selected.dataset.nodeId;
  const adjacency = new Map();
  Array.from(canvas.querySelectorAll('.node')).forEach(node => adjacency.set(node.dataset.nodeId, new Set()));
  Array.from(canvas.querySelectorAll('.edge')).forEach(edge => {
    if (!adjacency.has(edge.dataset.source) || !adjacency.has(edge.dataset.target)) return;
    adjacency.get(edge.dataset.source).add(edge.dataset.target);
    adjacency.get(edge.dataset.target).add(edge.dataset.source);
  });
  const keep = new Set([start]);
  const queue = [start];
  while (queue.length) {
    const id = queue.shift();
    adjacency.get(id).forEach(next => {
      if (keep.has(next)) return;
      keep.add(next);
      queue.push(next);
    });
  }
  layoutState.pathFocus = keep;
  applyTraceVisibility();
  document.getElementById('viewerStatus').textContent = 'Path-only view from ' + start + ': ' + keep.size + ' connected node(s).';
}
function nodeTraceText(item) {
  return (item.textContent + ' ' + Array.from(item.attributes || []).map(attr => attr.value).join(' ')).toLowerCase();
}
function applyScale() { canvas.style.transform = 'scale(' + scale.toFixed(2) + ')'; }
function currentSVG() { return canvas.querySelector('svg'); }
function serializedSVG() {
  const svg = currentSVG();
  if (!svg) return '';
  const clone = svg.cloneNode(true);
  clone.querySelectorAll('.selected, .matched, .dimmed').forEach(item => {
    item.classList.remove('selected', 'matched', 'dimmed');
  });
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  return new XMLSerializer().serializeToString(clone);
}
function downloadBlob(blob, filename) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}
function downloadInlineSVG() {
  const svg = serializedSVG();
  if (!svg) {
    document.getElementById('viewerStatus').textContent = 'SVG export is unavailable until the trace is loaded.';
    return;
  }
  downloadBlob(new Blob([svg], { type: 'image/svg+xml;charset=utf-8' }), 'providapt-trace-' + safeFilename(alertID) + '.svg');
  document.getElementById('viewerStatus').textContent = 'SVG export prepared from the current trace.';
}
function exportPNG() {
  const svg = currentSVG();
  const text = serializedSVG();
  if (!svg || !text) {
    document.getElementById('viewerStatus').textContent = 'PNG export is unavailable until the trace is loaded.';
    return;
  }
  const width = Number(svg.getAttribute('width')) || svg.viewBox.baseVal.width || 1200;
  const height = Number(svg.getAttribute('height')) || svg.viewBox.baseVal.height || 800;
  const image = new Image();
  const url = URL.createObjectURL(new Blob([text], { type: 'image/svg+xml;charset=utf-8' }));
  image.onload = () => {
    const targetScale = Math.min(2, Math.max(1, 1800 / Math.max(width, 1)));
    const out = document.createElement('canvas');
    out.width = Math.round(width * targetScale);
    out.height = Math.round(height * targetScale);
    const ctx = out.getContext('2d');
    ctx.fillStyle = '#0d1117';
    ctx.fillRect(0, 0, out.width, out.height);
    ctx.drawImage(image, 0, 0, out.width, out.height);
    out.toBlob(blob => {
      URL.revokeObjectURL(url);
      if (!blob) {
        document.getElementById('viewerStatus').textContent = 'PNG export failed while rendering the trace.';
        return;
      }
      downloadBlob(blob, 'providapt-trace-' + safeFilename(alertID) + '.png');
      document.getElementById('viewerStatus').textContent = 'PNG export prepared from the current trace.';
    }, 'image/png');
  };
  image.onerror = () => {
    URL.revokeObjectURL(url);
    document.getElementById('viewerStatus').textContent = 'PNG export failed while loading the SVG image.';
  };
  image.src = url;
}
function copyReportSnippet() {
  const report = buildReportSnippet();
  if (!report) {
    document.getElementById('viewerStatus').textContent = 'Report snippet is unavailable until the trace is loaded.';
    return;
  }
  writeClipboard(report, 'Investigation report snippet copied.');
}
function copySelectedDetail() {
  const selected = canvas.querySelector('.selected');
  if (!selected) {
    document.getElementById('viewerStatus').textContent = 'Select a trace element before copying detail.';
    return;
  }
  const detail = traceElementDetail(selected);
  const lines = ['### ' + detail.title];
  detail.rows.forEach(row => {
    if (row[1] !== undefined && row[1] !== null && String(row[1]).trim() !== '') {
      lines.push('- ' + row[0] + ': ' + String(row[1]));
    }
  });
  writeClipboard(lines.join('\n'), 'Selected element detail copied.');
}
function buildReportSnippet() {
  if (!currentSVG()) return '';
  const nodes = Array.from(canvas.querySelectorAll('.node'));
  const edges = Array.from(canvas.querySelectorAll('.edge'));
  const clusters = Array.from(canvas.querySelectorAll('.cluster'));
  const lines = [
    '## ProvidAPT Trace Investigation',
    '',
    '- Alert scope: ' + alertID,
    '- Nodes: ' + nodes.length,
    '- Edges: ' + edges.length,
    '- Cross-links: ' + canvas.querySelectorAll('.edge-cross').length,
    '- Folded clusters: ' + clusters.length,
    '',
    '### Notable Relations'
  ];
  edges.slice(0, 8).forEach((edge, index) => {
    lines.push((index + 1) + '. ' + (edge.dataset.event || edge.dataset.relation || 'event') + ': ' + (edge.dataset.source || '?') + ' -> ' + (edge.dataset.target || '?'));
    if (edge.dataset.detail) lines.push('   - Detail: ' + edge.dataset.detail);
  });
  if (edges.length > 8) lines.push('- ' + (edges.length - 8) + ' additional relation(s) omitted from this snippet.');
  if (clusters.length) {
    lines.push('', '### Folded Clusters');
    clusters.slice(0, 5).forEach(cluster => {
      lines.push('- ' + (cluster.dataset.nodeType || 'node') + ' depth ' + (cluster.dataset.depth || '?') + ': ' + (cluster.dataset.foldedCount || '0') + ' folded node(s)');
    });
  }
  return lines.join('\n');
}
function writeClipboard(text, successMessage) {
  const done = () => { document.getElementById('viewerStatus').textContent = successMessage; };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
    return;
  }
  fallbackCopy(text, done);
}
function fallbackCopy(text, done) {
  const area = document.createElement('textarea');
  area.value = text;
  area.style.position = 'fixed';
  area.style.left = '-9999px';
  document.body.appendChild(area);
  area.focus();
  area.select();
  document.execCommand('copy');
  area.remove();
  done();
}
function safeFilename(value) {
  return String(value || 'trace').replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'trace';
}
function zoomBy(delta) {
  scale = Math.max(0.25, Math.min(2.6, scale + delta));
  applyScale();
}
function fitWidth() {
  const svg = canvas.querySelector('svg');
  if (!svg) return;
  const width = Number(svg.getAttribute('width')) || svg.viewBox.baseVal.width || wrap.clientWidth;
  scale = Math.max(0.25, Math.min(1.4, (wrap.clientWidth - 24) / Math.max(width, 1)));
  applyScale();
}
function toggleCrossLinks() {
  canvas.classList.toggle('hide-cross');
  document.getElementById('viewerStatus').textContent = canvas.classList.contains('hide-cross')
    ? 'Cross-links are hidden. Tree causality remains visible.'
    : 'Cross-links are visible. Dashed links preserve non-tree evidence.';
}
function toggleClusters() {
  canvas.classList.toggle('cluster-highlight');
  const clusters = canvas.querySelectorAll('.cluster');
  document.getElementById('viewerStatus').textContent = canvas.classList.contains('cluster-highlight')
    ? (clusters.length + ' folded cluster(s) highlighted. Hover a cluster to inspect folded members and fold reason.')
    : 'Cluster highlight cleared. Folded nodes remain visible as dashed purple summary boxes.';
}
document.getElementById('searchBox').addEventListener('input', event => {
  const query = event.target.value.trim().toLowerCase();
  layoutState.searchQuery = query;
  const candidates = Array.from(canvas.querySelectorAll('.node, .edge, .event-group, .cluster'));
  let hits = 0;
  candidates.forEach(item => {
    item.classList.remove('matched', 'dimmed');
    if (!query) return;
    const matched = item.textContent.toLowerCase().includes(query) || Array.from(item.attributes || []).some(attr => attr.value.toLowerCase().includes(query));
    item.classList.toggle('matched', matched);
    item.classList.toggle('dimmed', !matched);
    if (matched) hits++;
  });
  if (query) {
    document.getElementById('viewerStatus').textContent = hits + ' matching trace element(s) for \"' + query + '\"';
  }
  applyTraceVisibility();
});
window.addEventListener('resize', () => window.requestAnimationFrame(fitWidth));
function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
</script>
</body>
</html>
`, escapeXML(alertID), escapeXML(alertID), rawPath, rawPath, reportMarkdownPath, reportPath, rawPath, alertID)
	return []byte(b.String())
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
	for _, cluster := range lay.clusters {
		maxDepth = maxInt(maxDepth, cluster.depth)
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
	for _, cluster := range lay.clusters {
		colWidths[cluster.depth] = maxInt(colWidths[cluster.depth], minNodeW)
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
		nodeDepth := depth[node.id]
		node.x = colX[nodeDepth]
		node.y = y
		lay.nodes = append(lay.nodes, node)
	}
	colY := make([]int, len(colWidths))
	for i := range colY {
		colY[i] = topY
	}
	for i := range lay.nodes {
		node := &lay.nodes[i]
		nodeDepth := depth[node.id]
		node.y = colY[nodeDepth]
		colY[nodeDepth] += node.h + yPad
	}
	for i := range lay.clusters {
		cluster := &lay.clusters[i]
		cluster.x = colX[cluster.depth]
		cluster.y = colY[cluster.depth]
		cluster.w = maxInt(minNodeW, colWidths[cluster.depth])
		cluster.h = 88
		colY[cluster.depth] += cluster.h + yPad
	}
	y = topY
	for _, nextY := range colY {
		y = maxInt(y, nextY)
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

func normalizeSVGLayoutMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "compact", "timeline", "grouped":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "tree"
	}
}

func applyServerSVGLayout(lay *svgLayout, mode string) {
	if lay == nil {
		return
	}
	lay.layoutMode = mode
	if mode == "tree" {
		return
	}
	switch mode {
	case "compact":
		arrangeSVGCompact(lay)
	case "timeline":
		arrangeSVGTimeline(lay)
	case "grouped":
		arrangeSVGGrouped(lay)
	}
	lay.graphH = maxInt(minGraphH, maxSVGContentY(lay)+40)
	lay.height = lay.graphH + eventTableHeight(lay.edges) + 50
}

func arrangeSVGCompact(lay *svgLayout) {
	byDepth := map[int][]int{}
	for i, node := range lay.nodes {
		byDepth[node.depth] = append(byDepth[node.depth], i)
	}
	depths := sortedIntKeys(byDepth)
	maxX := 0
	for col, depth := range depths {
		y := topY
		x := xPad + col*300
		for _, idx := range byDepth[depth] {
			lay.nodes[idx].x = x
			lay.nodes[idx].y = y
			y += lay.nodes[idx].h + 18
			maxX = maxInt(maxX, x+lay.nodes[idx].w)
		}
		for i := range lay.clusters {
			if lay.clusters[i].depth != depth {
				continue
			}
			lay.clusters[i].x = x
			lay.clusters[i].y = y
			lay.clusters[i].w = maxInt(minNodeW, columnWidth(lay, depth))
			y += lay.clusters[i].h + 18
			maxX = maxInt(maxX, lay.clusters[i].x+lay.clusters[i].w)
		}
	}
	lay.width = maxInt(1120, maxX+xPad)
}

func arrangeSVGTimeline(lay *svgLayout) {
	sort.SliceStable(lay.nodes, func(i, j int) bool {
		if lay.nodes[i].x == lay.nodes[j].x {
			return lay.nodes[i].y < lay.nodes[j].y
		}
		return lay.nodes[i].x < lay.nodes[j].x
	})
	maxX := 0
	for i := range lay.nodes {
		lay.nodes[i].x = 96 + lay.nodes[i].depth*28
		lay.nodes[i].y = topY + i*88
		maxX = maxInt(maxX, lay.nodes[i].x+lay.nodes[i].w)
	}
	y := topY + len(lay.nodes)*88 + 24
	for i := range lay.clusters {
		lay.clusters[i].x = 96 + lay.clusters[i].depth*28
		lay.clusters[i].y = y
		y += lay.clusters[i].h + 18
		maxX = maxInt(maxX, lay.clusters[i].x+lay.clusters[i].w)
	}
	lay.width = maxInt(1120, maxX+xPad)
}

func arrangeSVGGrouped(lay *svgLayout) {
	order := []string{"process", "file", "network", "credential", ""}
	rank := map[string]int{}
	for i, typ := range order {
		rank[typ] = i
	}
	sort.SliceStable(lay.nodes, func(i, j int) bool {
		left := rankOrDefault(rank, lay.nodes[i].typ)
		right := rankOrDefault(rank, lay.nodes[j].typ)
		if left == right {
			if lay.nodes[i].depth == lay.nodes[j].depth {
				return lay.nodes[i].id < lay.nodes[j].id
			}
			return lay.nodes[i].depth < lay.nodes[j].depth
		}
		return left < right
	})
	byType := map[string][]int{}
	for i, node := range lay.nodes {
		byType[node.typ] = append(byType[node.typ], i)
	}
	types := sortedSVGTypes(byType)
	maxX := 0
	for col, typ := range types {
		x := xPad + col*320
		y := topY
		for _, idx := range byType[typ] {
			lay.nodes[idx].x = x
			lay.nodes[idx].y = y
			y += lay.nodes[idx].h + 22
			maxX = maxInt(maxX, x+lay.nodes[idx].w)
		}
		for i := range lay.clusters {
			if lay.clusters[i].typ != typ {
				continue
			}
			lay.clusters[i].x = x
			lay.clusters[i].y = y
			lay.clusters[i].w = maxInt(minNodeW, typeColumnWidth(lay, typ))
			y += lay.clusters[i].h + 22
			maxX = maxInt(maxX, lay.clusters[i].x+lay.clusters[i].w)
		}
	}
	lay.width = maxInt(1120, maxX+xPad)
}

func maxSVGContentY(lay *svgLayout) int {
	y := topY
	for _, node := range lay.nodes {
		y = maxInt(y, node.y+node.h)
	}
	for _, cluster := range lay.clusters {
		y = maxInt(y, cluster.y+cluster.h)
	}
	return y
}

func columnWidth(lay *svgLayout, depth int) int {
	width := minNodeW
	for _, node := range lay.nodes {
		if node.depth == depth {
			width = maxInt(width, node.w)
		}
	}
	return width
}

func typeColumnWidth(lay *svgLayout, typ string) int {
	width := minNodeW
	for _, node := range lay.nodes {
		if node.typ == typ {
			width = maxInt(width, node.w)
		}
	}
	return width
}

func sortedIntKeys(groups map[int][]int) []int {
	keys := make([]int, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	return keys
}

func sortedSVGTypes(groups map[string][]int) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := svgTypeRank(keys[i])
		right := svgTypeRank(keys[j])
		if left == right {
			return keys[i] < keys[j]
		}
		return left < right
	})
	return keys
}

func svgTypeRank(typ string) int {
	switch typ {
	case "process":
		return 0
	case "file":
		return 1
	case "network":
		return 2
	case "credential":
		return 3
	default:
		return 9
	}
}

func rankOrDefault(rank map[string]int, key string) int {
	if value, ok := rank[key]; ok {
		return value
	}
	return 9
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
			title:   fmt.Sprintf("Folded %s nodes", displayType(key.typ)),
			count:   len(members),
			typ:     key.typ,
			depth:   key.depth,
			members: members,
			reason:  fmt.Sprintf("same layer/type exceeded %d visible node limit", clusterKeep),
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
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" data-layout="%s" preserveAspectRatio="xMidYMin meet" style="max-width:100vw;height:auto;display:block;margin:0 auto;background:#0d1117;">
<style>
  .bg { fill: #0d1117; }
  .node rect { stroke-width: 1.2; rx: 8; }
  .cluster rect { fill: #151923; stroke: #a371f7; stroke-width: 1.4; rx: 10; stroke-dasharray: 6 4; }
  .cluster .label { fill: #f0f6fc; font: 12px monospace; font-weight: 700; }
  .cluster .badge { fill: #d8b9ff; font: 10px monospace; font-weight: 700; }
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
  .legend rect { fill: rgba(13,17,23,.92); stroke: #30363d; rx: 8; }
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
<text x="18" y="54" class="subtitle">Tree layout is left-to-right; Causal direction is rendered as source -&gt; target; folded clusters summarize same-layer/type nodes while preserving full member tooltips.</text>
`, lay.width, lay.height, lay.width, lay.height, escapeXML(firstNonEmpty(lay.layoutMode, "tree")), svgMarkers(), lay.width, lay.height, escapeXML(scope))

	nodeMap := make(map[string]svgNode)
	for _, n := range lay.nodes {
		nodeMap[n.id] = n
	}
	for _, cluster := range lay.clusters {
		fmt.Fprintf(&b, `<g class="cluster cluster-%s" data-cluster-id="%s" data-depth="%d" data-node-type="%s" data-folded-count="%d" data-members="%s" data-reason="%s">
  <title>%s</title>
  <rect x="%d" y="%d" width="%d" height="%d"/>
  <text class="label" x="%d" y="%d">%s</text>
  <text class="badge" x="%d" y="%d">%d folded - depth %d</text>
  <text class="meta" x="%d" y="%d">%s</text>
  <text class="meta" x="%d" y="%d">%s</text>
</g>
`, escapeXML(cluster.typ), escapeXML(cluster.id), cluster.depth, escapeXML(cluster.typ), cluster.count, escapeXML(strings.Join(cluster.members, ", ")), escapeXML(cluster.reason), escapeXML(clusterTitle(cluster)), cluster.x, cluster.y, cluster.w, cluster.h, cluster.x+10, cluster.y+20, escapeXML(cluster.title), cluster.x+10, cluster.y+36, cluster.count, cluster.depth, cluster.x+10, cluster.y+52, escapeXML(cluster.reason), cluster.x+10, cluster.y+68, escapeXML(clusterMemberPreview(cluster)))
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
		fmt.Fprintf(&b, `<g class="edge %s edge-%s edge-%s" data-source="%s" data-target="%s" data-relation="%s" data-kind="%s" data-event="%s" data-summary="%s" data-detail="%s" data-direction="%s-&gt;%s" data-tree="%t">
  <path d="%s"/>
  <text class="edge-label-%s" x="%d" y="%d">%s -&gt;</text>
</g>
`, edgeClass, e.rel, e.kind, escapeXML(e.src), escapeXML(e.dst), escapeXML(e.rel), escapeXML(e.kind), escapeXML(e.event), escapeXML(e.summary), escapeXML(e.detail), escapeXML(e.src), escapeXML(e.dst), e.tree, edgePath(x1, y1, x2, y2), e.kind, midX+edgeLabelDX, labelY, escapeXML(e.event))
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
		fmt.Fprintf(&b, `<g class="node %s" data-node-id="%s" data-node-type="%s" data-depth="%d" data-node-label="%s" data-detail="%s" data-identity="%s">
  <title>%s</title>
  <rect x="%d" y="%d" width="%d" height="%d"/>
  %s
</g>
`, class, escapeXML(n.id), escapeXML(n.typ), n.depth, escapeXML(n.label), escapeXML(n.detail1), escapeXML(n.detail2), escapeXML(nodeTitle(n)), n.x, n.y, n.w, n.h, renderNodeText(n))
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
			for lineIndex, line := range wrapText(summary, 132) {
				fmt.Fprintf(b, `  <text x="52" y="%d">%s</text>
`, rowY+lineIndex*12, escapeXML(line))
			}
			detailStartY := rowY + len(wrapText(summary, 132))*12
			for lineIndex, line := range wrapText(e.detail, 132) {
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
	return 10 + len(wrapText(summary, 132))*12 + len(wrapText(edge.detail, 132))*12
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
	x := maxInt(360, width-180)
	fmt.Fprintf(b, `<g class="legend" transform="translate(%d,12)">
<rect x="-10" y="-8" width="170" height="%d"/>
`, x, len(items)*18+10)
	for i, item := range items {
		y := i * 18
		fmt.Fprintf(b, `<line x1="0" y1="%d" x2="18" y2="%d" stroke="%s" stroke-width="2"/>
<text x="24" y="%d">%s</text>`, y, y, item.color, y+4, escapeXML(item.label))
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

func makeSVGNode(n *provenance.Node, depth int) svgNode {
	node := svgNode{
		id:      n.ID,
		label:   n.Label,
		detail1: nodeDetailLine(n),
		detail2: nodeIdentityLine(n),
		typ:     n.Subtype,
		depth:   depth,
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
		for _, line := range wrapText(group.text, widthChars) {
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

func wrapText(text string, width int) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	var lines []string
	for len(text) > width {
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
