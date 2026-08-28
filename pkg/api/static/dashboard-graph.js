function countBy(items, pick) {
  const counts = {};
  items.forEach(item => {
    const key = pick(item) || 'unknown';
    counts[key] = (counts[key] || 0) + 1;
  });
  return Object.keys(counts).sort().map(key => ({ key: key, count: counts[key] }));
}

function graphElementID(item) {
  const data = item && item.data ? item.data : {};
  return String(data.id || data.node_id || data.label || item.id || '');
}

function graphElementType(item) {
  const data = item && item.data ? item.data : {};
  return String(data.type || data.subtype || data.label || item.group || 'unknown');
}

function graphClusterKey(item) {
  const data = item && item.data ? item.data : {};
  const type = graphElementType(item);
  const label = String(data.label || data.name || data.id || '');
  if (type === 'process') return 'process:' + String(data.comm || label.split('[')[0] || 'unknown');
  if (type === 'file') return 'file:' + (label.indexOf('/') >= 0 ? label.split('/').slice(0, -1).join('/') || '/' : 'inode');
  if (type === 'network') return 'network:' + String(data.protocol || data.address_family || 'socket');
  return type;
}

function graphClusterRows(nodes, edges) {
  const degree = {};
  edges.forEach(edge => {
    const data = edge.data || {};
    if (data.source) degree[String(data.source)] = (degree[String(data.source)] || 0) + 1;
    if (data.target) degree[String(data.target)] = (degree[String(data.target)] || 0) + 1;
  });
  const clusters = {};
  nodes.forEach(node => {
    const key = graphClusterKey(node);
    clusters[key] = clusters[key] || { key: key, nodes: 0, edges: 0, max_degree: 0, sample: graphElementID(node) };
    clusters[key].nodes += 1;
    clusters[key].max_degree = Math.max(clusters[key].max_degree, degree[graphElementID(node)] || 0);
  });
  edges.forEach(edge => {
    const sourceCluster = clusters[graphClusterKey(nodes.find(node => graphElementID(node) === String((edge.data || {}).source)) || {})];
    const targetCluster = clusters[graphClusterKey(nodes.find(node => graphElementID(node) === String((edge.data || {}).target)) || {})];
    if (sourceCluster) sourceCluster.edges += 1;
    if (targetCluster && targetCluster !== sourceCluster) targetCluster.edges += 1;
  });
  return Object.values(clusters).sort((a, b) => (b.nodes + b.edges + b.max_degree) - (a.nodes + a.edges + a.max_degree));
}

function renderGraphClusterRows(nodes, edges) {
  return graphClusterRows(nodes, edges).slice(0, 12).map(cluster => '<div class="alert-item">' +
    '<span class="alert-sev sev-medium">cluster</span>' +
    '<span class="alert-msg">' + escapeHTML(cluster.key) + ' · ' + cluster.nodes + ' nodes · ' + cluster.edges + ' linked edges · max degree ' + cluster.max_degree +
    '<span class="graph-cluster-actions">' +
    '<button onclick="collapseGraphCluster(\'' + jsString(cluster.key) + '\')">Inspect</button>' +
    '<button onclick="exportClusterSubset(\'' + jsString(cluster.key) + '\')">Export Cluster</button>' +
    '</span></span>' +
    '<span class="alert-time">cluster view</span>' +
    '</div>');
}

function graphTopHubs(nodes, edges) {
  const degree = {};
  edges.forEach(edge => {
    const data = edge.data || {};
    if (data.source) degree[String(data.source)] = (degree[String(data.source)] || 0) + 1;
    if (data.target) degree[String(data.target)] = (degree[String(data.target)] || 0) + 1;
  });
  return nodes.map(node => ({
    id: graphElementID(node),
    type: graphElementType(node),
    degree: degree[graphElementID(node)] || 0,
  })).sort((a, b) => b.degree - a.degree).slice(0, 8);
}

async function collapseGraphCluster(clusterKey) {
  setInvestigationLoading('Filtering provenance cluster ' + clusterKey + '...');
  try {
    const data = await fetchJSON('/api/v1/graph/export');
    const subset = graphSubsetForCluster(data, clusterKey);
    const items = [
      '<div class="graph-subset-summary">' +
      renderMiniMetric('nodes', subset.nodes.length, 'in cluster') +
      renderMiniMetric('edges', subset.edges.length, 'linked') +
      renderMiniMetric('boundary', subset.boundary_edges.length, 'outside links') +
      '</div>',
      '<div class="alert-item"><span class="alert-sev sev-medium">actions</span><span class="alert-msg"><span class="graph-cluster-actions">' +
      '<button onclick="exportClusterSubset(\'' + jsString(clusterKey) + '\')">Download Filtered JSON</button>' +
      '<button onclick="showGraphSummary(\'nodes\')">Back To Summary</button>' +
      '</span></span><span class="alert-time">cluster</span></div>',
    ];
    subset.nodes.slice(0, 24).forEach(node => {
      const id = graphElementID(node);
      const type = graphElementType(node);
      const label = ((node.data || {}).label || (node.data || {}).comm || id || '').slice(0, 180);
      items.push('<div class="alert-item">' +
        '<span class="alert-sev sev-low">' + escapeHTML(type) + '</span>' +
        '<span class="alert-msg">' + escapeHTML(label || id || '--') + '<span class="graph-cluster-actions">' +
        '<button onclick="openGraphTrace(\'' + jsString(id) + '\', \'backward\')">Backward</button>' +
        '<button onclick="openGraphTrace(\'' + jsString(id) + '\', \'forward\')">Forward</button>' +
        '</span></span>' +
        '<span class="alert-time">' + escapeHTML(id) + '</span>' +
        '</div>');
    });
    setInvestigationItems(items, 'No nodes in cluster ' + clusterKey);
  } catch (e) {
    setInvestigationLoading('Cluster filter unavailable: ' + e.message);
  }
}

function graphSubsetForCluster(data, clusterKey) {
  const elements = data.elements || [];
  const nodes = elements.filter(item => !item.data || !item.data.source);
  const edges = elements.filter(item => item.data && item.data.source);
  const selectedNodes = nodes.filter(node => graphClusterKey(node) === clusterKey);
  const selectedIDs = {};
  selectedNodes.forEach(node => { selectedIDs[graphElementID(node)] = true; });
  const selectedEdges = edges.filter(edge => selectedIDs[String((edge.data || {}).source)] && selectedIDs[String((edge.data || {}).target)]);
  const boundaryEdges = edges.filter(edge => selectedIDs[String((edge.data || {}).source)] !== selectedIDs[String((edge.data || {}).target)]);
  return { nodes: selectedNodes, edges: selectedEdges, boundary_edges: boundaryEdges };
}

async function exportClusterSubset(clusterKey) {
  try {
    const data = await fetchJSON('/api/v1/graph/export');
    const subset = graphSubsetForCluster(data, clusterKey);
    const payload = {
      schema: 'providapt.dashboard_graph_subset.v1',
      generated_at: new Date().toISOString(),
      cluster: clusterKey,
      summary: {
        nodes: subset.nodes.length,
        edges: subset.edges.length,
        boundary_edges: subset.boundary_edges.length,
      },
      elements: subset.nodes.concat(subset.edges),
      boundary_edges: subset.boundary_edges,
    };
    downloadTextFile('providapt-graph-' + clusterKey.replace(/[^A-Za-z0-9_.-]+/g, '_') + '.json', JSON.stringify(payload, null, 2) + '\n');
    setInvestigationItems([renderKVItem('graph export', clusterKey, subset.nodes.length + ' nodes · ' + subset.edges.length + ' edges')], 'Graph export prepared');
  } catch (e) {
    setInvestigationLoading('Graph export failed: ' + e.message);
  }
}

function openGraphTrace(nodeID, direction) {
  if (!nodeID) return;
  openProtectedEndpoint('/api/v1/graph/node/' + encodeURIComponent(nodeID) + '/' + direction + '?depth=8', 'providapt-graph-trace.json');
}

function openGraphFullscreen() {
  openProtectedEndpoint('/api/v1/graph/export', 'providapt-graph.json');
  openDetailDrawer('Graph Fullscreen', 'Opened graph JSON in a new tab', [
    renderKVItem('primary view', '/api/v1/graph/export', 'new tab'),
    renderKVItem('next step', 'Use Nodes or Route Map to reduce clutter before opening node traces.', 'workflow'),
  ].join(''));
}

async function showAttackRouteMap() {
  setInvestigationLoading('Building attack route map from graph topology...');
  try {
    const data = await fetchJSON('/api/v1/graph/export');
    const elements = data.elements || [];
    const nodes = elements.filter(item => !item.data || !item.data.source);
    const edges = elements.filter(item => item.data && item.data.source);
    const hubs = graphTopHubs(nodes, edges);
    const clusters = graphClusterRows(nodes, edges).slice(0, 8);
    const items = [
      renderKVItem('route map', nodes.length + ' nodes · ' + edges.length + ' directed edges', 'topology summary'),
      renderKVItem('directionality', 'source -> target', 'use Backward for cause, Forward for impact'),
    ];
    hubs.forEach(hub => {
      items.push('<div class="alert-item"><span class="alert-sev sev-high">hub</span><span class="alert-msg">' +
        escapeHTML(hub.id || 'unknown') + ' · ' + escapeHTML(hub.type || 'unknown') + ' · degree ' + hub.degree +
        '<span class="graph-cluster-actions">' +
        '<button onclick="openGraphTrace(\'' + jsString(hub.id) + '\', \'backward\')">Cause</button>' +
        '<button onclick="openGraphTrace(\'' + jsString(hub.id) + '\', \'forward\')">Impact</button>' +
        '</span></span><span class="alert-time">route</span></div>');
    });
    clusters.forEach(cluster => items.push('<div class="alert-item"><span class="alert-sev sev-medium">cluster</span><span class="alert-msg">' + escapeHTML(cluster.key) + ' · ' + cluster.nodes + ' nodes · ' + cluster.edges + ' edges<span class="graph-cluster-actions"><button onclick="collapseGraphCluster(\'' + jsString(cluster.key) + '\')">Inspect</button></span></span><span class="alert-time">group</span></div>'));
    setInvestigationItems(items, 'No attack route topology available');
    openDetailDrawer('Route Map', 'Topology summary with directed cause/impact actions', items.join(''));
  } catch (e) {
    setInvestigationLoading('Attack route map unavailable: ' + e.message);
  }
}

async function showGraphSummary(kind) {
  if (currentRole === 'auditor') {
    setInvestigationLoading('Graph export is hidden for auditor role');
    return;
  }
  setInvestigationLoading('Loading graph ' + kind + '...');
  try {
    const data = await fetchJSON('/api/v1/graph/export');
    const elements = data.elements || [];
    const nodes = elements.filter(item => !item.data || !item.data.source);
    const edges = elements.filter(item => item.data && item.data.source);
    const selected = kind === 'edges' ? edges : nodes;
    const groups = countBy(selected, item => item.data && (item.data.type || item.data.label || item.group));
    const items = groups.map(group => '<div class="alert-item">' +
      '<span class="alert-sev sev-medium">' + escapeHTML(kind) + '</span>' +
      '<span class="alert-msg">' + escapeHTML(group.key) + ' · ' + group.count + ' item(s)' +
      ' · <a class="console-link" href="/api/v1/graph/export" target="_blank" rel="noreferrer">export JSON</a></span>' +
      '<span class="alert-time">' + nodes.length + ' nodes / ' + edges.length + ' edges</span>' +
      '</div>');
    if (kind === 'nodes') {
      items.push(...renderGraphClusterRows(nodes, edges));
      graphTopHubs(nodes, edges).forEach(hub => {
        items.push(renderKVItem('high-degree hub', hub.id || 'unknown', hub.type + ' · degree ' + hub.degree));
      });
    }
    setInvestigationItems(items, 'No graph ' + kind + ' available');
  } catch (e) {
    setInvestigationLoading('Graph summary unavailable: ' + e.message);
  }
}
