const traceViewerConfig = document.getElementById('traceViewerApp')?.dataset || {};
const rawURL = traceViewerConfig.rawUrl || '';
const alertID = traceViewerConfig.alertId || '';
let scale = 1;
const canvas = document.getElementById('canvas');
const wrap = document.getElementById('canvasWrap');
const layoutState = { mode: 'tree', typeFilter: 'all', collapsedTypes: new Set(), searchQuery: '', pathFocus: new Set() };

fetch(traceFetchURL(), { cache: 'no-store' })
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

function traceFetchURL() {
  try {
    return new URL(rawURL, window.location.origin).toString();
  } catch (error) {
    return '/api/v1/alerts/' + encodeURIComponent(alertID) + '/svg';
  }
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
  canvas.innerHTML = '<div class="card status">Loading raw SVG fallback...</div>';
  setMetric('nodeCount', '--');
  setMetric('edgeCount', '--');
  setMetric('crossCount', '--');
  setMetric('clusterCount', '--');
  document.getElementById('detailPanel').className = 'detail-empty';
  document.getElementById('detailPanel').textContent = 'Trace details are unavailable while the raw SVG fallback is active.';
  scale = 1;
  applyScale();
  fetch(traceFetchURL(), { cache: 'no-store' })
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
        ? 'Trace SVG was blocked by the running daemon or proxy. Upgrade the daemon to the open-source control-plane build and check proxy policy.'
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
