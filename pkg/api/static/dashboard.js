// Dashboard module actions and refresh loop.

async function loadSupportBundles() {
  try {
    const data = await fetchJSON('/api/v1/control/support');
    const auditData = await fetchJSON('/api/v1/control/audit?category=admin&source=supportbundle&limit=8');
    latestSupport = Object.assign({}, data, { audit_entries: (auditData && auditData.entries) || [] });
    const history = data.history || [];
    document.getElementById('sbStatus').textContent = data.last_status || '--';
    document.getElementById('sbTime').textContent = data.last_bundle_at ? formatTime(data.last_bundle_at) : '--';
    document.getElementById('sbActor').textContent = data.last_actor || '--';
    document.getElementById('sbHistoryCount').textContent = history.length;
    const downloadBtn = document.getElementById('downloadSupportBundleBtn');
    if (downloadBtn) {
      downloadBtn.disabled = currentRole === 'analyst' || !data.download_url;
    }

    const details = document.getElementById('supportBundleDetails');
    if (!data.last_bundle_path && history.length === 0) {
      details.innerHTML = '<div class="loading">No support bundles exported yet</div>';
      return;
    }

    const items = [];
    if (data.last_bundle_path) {
      items.push('<div class="alert-item">' +
        '<span class="alert-sev sev-medium">latest</span>' +
        '<span class="alert-msg">' + (data.last_archive_path || data.last_bundle_path || '--') + (data.redacted ? ' · redacted zip' : '') + (data.last_reason ? (' · ' + data.last_reason) : '') + '</span>' +
        '<span class="alert-time">' + formatTime(data.last_bundle_at) + '</span>' +
        '</div>');
    }
    items.push(...history.slice(0, 8).map(item => {
      const actor = item.actor ? ' · ' + item.actor : '';
      const note = item.note ? ' · note: ' + item.note : '';
      const target = item.target_id ? ' · ' + item.target_id : '';
      return '<div class="alert-item">' +
        '<span class="alert-sev ' + (String(item.status || '').indexOf('fail') >= 0 ? 'sev-critical' : 'sev-low') + '">' + (item.action || 'action') + '</span>' +
        '<span class="alert-msg">' + (item.message || item.status || 'done') + actor + target + note + '</span>' +
        '<span class="alert-time">' + formatTime(item.performed_at) + '</span>' +
        '</div>';
    }));
    details.innerHTML = items.join('');

    const auditList = document.getElementById('supportBundleAuditList');
    const auditEntries = (auditData && auditData.entries) || [];
    if (auditList) {
      if (auditEntries.length === 0) {
        auditList.innerHTML = '<div class="loading">No persisted support bundle audit entries yet</div>';
      } else {
        auditList.innerHTML = auditEntries.map(item => {
          const actor = item.details && item.details.actor ? (' · ' + item.details.actor) : '';
          const path = item.details && (item.details.archive_path || item.details.bundle_path) ? (' · ' + (item.details.archive_path || item.details.bundle_path)) : '';
          return '<div class="alert-item">' +
            '<span class="alert-sev ' + ((item.severity || '') === 'WARNING' ? 'sev-high' : 'sev-low') + '">' + (item.category || 'audit') + '</span>' +
            '<span class="alert-msg">' + (item.message || 'audit event') + actor + path + '</span>' +
            '<span class="alert-time">' + formatTime(item.timestamp) + '</span>' +
            '</div>';
        }).join('');
      }
    }
  } catch (e) {
    document.getElementById('supportBundleDetails').innerHTML = '<div class="loading">Support bundle state unavailable</div>';
    const auditList = document.getElementById('supportBundleAuditList');
    if (auditList) {
      auditList.innerHTML = '<div class="loading">Persisted support bundle audit unavailable</div>';
    }
  }
}

function showSupportDetails(scope) {
  const data = latestSupport || {};
  const history = data.history || [];
  const audit = data.audit_entries || [];
  const items = [
    renderKVItem('status', data.last_status || '--', formatTime(data.last_bundle_at || data.last_archive_at)),
    renderKVItem('bundle', data.last_bundle_path || '--', data.redacted ? 'redacted' : 'raw'),
    renderKVItem('archive', data.last_archive_path || '--', data.download_url || ''),
    renderKVItem('actor', data.last_actor || '--', data.last_role || ''),
  ];
  if (scope === 'history') {
    history.slice(0, 8).forEach(item => items.push(renderKVItem(item.action || 'action', (item.message || item.status || 'done') + (item.note ? (' · ' + item.note) : ''), formatTime(item.performed_at))));
    audit.slice(0, 8).forEach(item => items.push(renderKVItem(item.category || 'audit', item.message || 'audit event', formatTime(item.timestamp))));
  }
  setInvestigationItems(items, 'No support bundle details available');
}

async function runSupportBundleAction(payload) {
  const status = document.getElementById('supportBundleStatus');
  const exportBtn = document.getElementById('exportSupportBundleBtn');
  if (status) {
    status.textContent = 'Exporting support bundle...';
  }
  if (exportBtn) exportBtn.disabled = true;
  try {
    const data = await postJSON('/api/v1/control/support', payload);
    if (status) {
      status.textContent = (data.message || 'Support bundle exported') + (data.bundle_path ? (': ' + data.bundle_path) : '');
    }
    await loadSupportBundles();
  } catch (e) {
    if (status) {
      status.textContent = 'Support bundle export failed: ' + e.message;
    }
  } finally {
    if (exportBtn) exportBtn.disabled = currentRole !== 'admin';
  }
}

function prepareSupportBundleAction() {
  if (!requireAdminAction('Support bundle export')) {
    return;
  }
  runSupportBundleAction({ reason: 'dashboard', note: supportBundleNote() });
}

function supportBundleNote() {
  const range = policyInputValue('supportBundleRange') || 'latest';
  const includes = policyInputValue('supportBundleIncludes') || 'default';
  const redaction = policyInputValue('supportBundleRedaction') || 'standard';
  return 'dashboard export · range=' + range + ' · include=' + includes + ' · redaction=' + redaction;
}

async function downloadSupportBundle() {
  if (currentRole === 'analyst') {
    return;
  }
  try {
    await downloadWithAuth('/api/v1/control/support/download', 'providapt-support-bundle.zip');
  } catch (e) {
    const status = document.getElementById('supportBundleStatus');
    if (status) status.textContent = 'Download failed: ' + e.message;
  }
}

async function loadBackups() {
  try {
    const data = await fetchJSON('/api/v1/control/backup');
    latestBackup = data || {};
    const history = data.history || [];
    setText('bkStatus', data.last_status || '--');
    setText('bkTime', data.last_backup_at ? formatTime(data.last_backup_at) : '--');
    setText('bkRestore', data.last_restore_at ? formatTime(data.last_restore_at) : '--');
    setText('bkHistoryCount', history.length);
    const downloadBtn = document.getElementById('downloadBackupBtn');
    if (downloadBtn) {
      downloadBtn.disabled = currentRole !== 'admin' || !data.download_url;
    }

    const details = document.getElementById('backupDetails');
    if (!details) return;
    if (!data.last_backup_path && history.length === 0) {
      details.innerHTML = '<div class="loading">No backups created yet</div>';
      return;
    }
    const items = [];
    if (data.last_backup_path) {
      items.push('<div class="alert-item">' +
        '<span class="alert-sev sev-medium">backup</span>' +
        '<span class="alert-msg">' + escapeHTML(data.last_backup_path) + ' · ' + formatBytes(data.size_bytes || 0) + (data.last_message ? (' · ' + escapeHTML(data.last_message)) : '') + '</span>' +
        '<span class="alert-time">' + formatTime(data.last_backup_at) + '</span>' +
        '</div>');
    }
    if (data.last_restore_path) {
      items.push('<div class="alert-item">' +
        '<span class="alert-sev sev-low">restore</span>' +
        '<span class="alert-msg">staging path: ' + escapeHTML(data.last_restore_path) + '</span>' +
        '<span class="alert-time">' + formatTime(data.last_restore_at) + '</span>' +
        '</div>');
    }
    items.push(...history.slice(0, 8).map(item => {
      const target = item.target_id ? ' · ' + item.target_id : '';
      const note = item.note ? ' · note: ' + item.note : '';
      return '<div class="alert-item">' +
        '<span class="alert-sev ' + (String(item.status || '').indexOf('fail') >= 0 ? 'sev-critical' : 'sev-low') + '">' + escapeHTML(item.action || 'action') + '</span>' +
        '<span class="alert-msg">' + escapeHTML(item.message || item.status || 'done') + escapeHTML(target + note) + '</span>' +
        '<span class="alert-time">' + formatTime(item.performed_at) + '</span>' +
        '</div>';
    }));
    details.innerHTML = items.join('');
  } catch (e) {
    const details = document.getElementById('backupDetails');
    if (details) details.innerHTML = '<div class="loading">Backup state unavailable</div>';
  }
}

function showBackupDetails(scope) {
  const data = latestBackup || {};
  const history = data.history || [];
  const items = [
    renderKVItem('status', data.last_status || '--', data.last_message || ''),
    renderKVItem('backup', data.last_backup_path || '--', formatBytes(data.size_bytes || 0)),
    renderKVItem('restore staging', data.last_restore_path || '--', formatTime(data.last_restore_at)),
    renderKVItem('download', data.download_url || '--', 'admin only'),
  ];
  if (scope === 'history') {
    history.slice(0, 10).forEach(item => items.push(renderKVItem(item.action || 'action', (item.message || item.status || 'done') + (item.note ? (' · ' + item.note) : ''), formatTime(item.performed_at))));
  }
  setInvestigationItems(items, 'No backup details available');
}

async function runBackupAction(action) {
  if (!requireAdminAction('Backup action')) return;
  const status = document.getElementById('backupStatus');
  if (action === 'prepare_cutover' && !latestBackup.last_restore_path) {
    if (status) {
      status.textContent = 'Prepare cutover blocked: restore a backup to staging first and verify the staging path.';
    }
    showBackupDetails('restore');
    return;
  }
  if (status) {
    status.textContent = action === 'create'
      ? 'Creating checkpoint backup...'
      : (action === 'prepare_cutover' ? 'Preparing restore cutover plan...' : 'Restoring backup to staging...');
  }
  try {
    const data = await postJSON('/api/v1/control/backup', { action: action, note: 'dashboard ' + action });
    if (status) {
      status.textContent = (data.message || data.status || 'done') + (data.backup_path ? (': ' + data.backup_path) : '');
    }
    await loadBackups();
  } catch (e) {
    if (status) status.textContent = 'Backup action failed: ' + e.message;
  }
}

async function downloadBackupArchive() {
  if (!requireAdminAction('Backup download')) return;
  try {
    await downloadWithAuth('/api/v1/control/backup/download', 'providapt-backup.tar.gz');
  } catch (e) {
    const status = document.getElementById('backupStatus');
    if (status) status.textContent = 'Backup download failed: ' + e.message;
  }
}

async function downloadPolicyBundle() {
  if (currentRole === 'analyst') {
    return;
  }
  const current = latestPolicies && latestPolicies.current ? latestPolicies.current : {};
  const version = Number(current.version || 0);
  try {
    await downloadWithAuth('/api/v1/control/policies/bundle' + (version > 0 ? ('?version=' + encodeURIComponent(version)) : ''), 'providapt-policy.json');
  } catch (e) {
    const status = document.getElementById('policyActionStatus');
    if (status) status.textContent = 'Policy bundle download failed: ' + e.message;
  }
}

async function downloadAuditCSV(source) {
  if (currentRole === 'analyst') {
    return;
  }
  const params = new URLSearchParams({ category: 'admin', limit: '200', format: 'csv' });
  if (source) params.set('source', source);
  try {
    await downloadWithAuth('/api/v1/control/audit?' + params.toString(), 'providapt-audit.csv');
  } catch (e) {
    const status = document.getElementById('supportBundleStatus');
    if (status) status.textContent = 'Audit export failed: ' + e.message;
  }
}

async function loadUpgradeStatus() {
  try {
    const upgrade = await fetchJSON('/api/v1/control/upgrade');
    latestUpgrade = upgrade;
    setCompactVersionText('topVersion', upgrade.current_version || '--');
    if (location.hash === '#version-update') {
      renderUpgradePage();
    }
  } catch (e) {
    setCompactVersionText('topVersion', '--');
  }
}

function openUpgradePage() {
  location.hash = 'version-update';
  renderUpgradePage();
}

function renderUpgradePage() {
  const upgrade = latestUpgrade || {};
  const actionHTML = `<span class="delivery-inline-actions"><button id="discoverUpgradeBtn" data-module="version-update" data-module-action="discover" onclick="prepareUpgradeAction('discover')">Discover</button><button id="checkUpgradeBtn" data-module="version-update" data-module-action="check" class="secondary" onclick="prepareUpgradeAction('check')">Record Check</button><button id="preflightUpgradeBtn" data-module="version-update" data-module-action="preflight" onclick="prepareUpgradeAction('preflight')">Preflight</button><button id="downloadUpgradeBtn" data-module="version-update" data-module-action="download" class="secondary" onclick="prepareUpgradeAction('download')">Download</button><button data-module="version-update" data-module-action="apply" class="secondary" onclick="prepareUpgradeAction('apply')">Apply</button><button data-module="version-update" data-module-action="rollback" class="secondary" onclick="prepareUpgradeAction('rollback')">Rollback</button><button id="recordUpgradeBtn" data-module="version-update" data-module-action="record" class="secondary" onclick="prepareUpgradeAction('record')">Record Note</button></span>`;
  const items = [
    renderKVItem('page', 'Version Update', 'upgrade'),
    renderKVItem('version', upgrade.current_version || '--', 'current'),
    renderKVItem('manifest', upgrade.manifest_url || '--', upgrade.download_url ? ('download ' + upgrade.download_url) : 'release discovery endpoint'),
    '<div class="alert-item"><span class="alert-sev sev-low">input</span><span class="alert-msg"><span class="compact-input-grid"><input id="upgradeManifestURL" value="' + escapeHTML(upgrade.manifest_url || '') + '" aria-label="Release manifest URL"></span></span><span class="alert-time">config</span></div>',
    renderKVItem('status', upgrade.preflight_ready ? 'ready to upgrade' : 'preflight required', upgrade.package_verified ? 'package verified' : 'package pending'),
    renderKVItem('execution', 'canary ' + (upgrade.canary_percent || 0) + '%', (upgrade.applied_at ? ('applied ' + formatTime(upgrade.applied_at)) : '') + (upgrade.rolled_back_at ? (' · rolled back ' + formatTime(upgrade.rolled_back_at)) : '')),
    '<div class="alert-item"><span class="alert-sev sev-medium">actions</span><span class="alert-msg">' + actionHTML + '</span><span class="alert-time">admin</span></div>',
  ];
  setInvestigationItems(items, 'Version update details unavailable');
}

function showUpgradeDetails() {
  const upgrade = latestUpgrade || {};
  const items = [
    renderKVItem('version', upgrade.current_version || '--', 'current'),
    renderKVItem('manifest', upgrade.manifest_url || '--', upgrade.download_url ? ('download ' + upgrade.download_url) : 'release discovery endpoint'),
    renderKVItem('package', (upgrade.package_path || '--') + ' · ' + (upgrade.package_verified ? 'verified' : 'not verified'), upgrade.package_sha256 ? upgrade.package_sha256.slice(0, 12) : ''),
    renderKVItem('signature', upgrade.signature_path || '--', upgrade.signature_verified ? 'verified' : (upgrade.signature_present ? 'mismatch' : 'not present')),
    renderKVItem('preflight', upgrade.preflight_ready ? 'ready' : 'not ready', upgrade.rollback_ready ? 'rollback ready' : 'rollback not ready'),
    renderKVItem('execution', 'canary ' + (upgrade.canary_percent || 0) + '%', (upgrade.applied_at ? ('applied ' + formatTime(upgrade.applied_at)) : '') + (upgrade.rolled_back_at ? (' · rolled back ' + formatTime(upgrade.rolled_back_at)) : '')),
  ];
  (upgrade.history || []).slice(0, 5).forEach(item => items.push(renderKVItem(item.action || 'upgrade', item.message || item.status || 'done', formatTime(item.performed_at))));
  setInvestigationItems(items, 'No upgrade details available');
}

function prepareUpgradeAction(action) {
  if (!requireAdminAction('Upgrade action')) {
    return;
  }
  const payload = modulePayload('version-update', action);
  if (action === 'discover') {
    const manifestInput = document.getElementById('upgradeManifestURL');
    const manifestURL = (manifestInput && manifestInput.value ? manifestInput.value.trim() : '') || (latestUpgrade && latestUpgrade.manifest_url) || '';
    if (!manifestURL) {
      setInvestigationItems([renderKVItem('manifest required', 'Set the release manifest URL before discovery', 'Version Update')], 'Manifest URL required');
      return;
    }
    payload.manifest_url = manifestURL;
  }
  runUpgradeAction(payload);
}

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
    renderKVItem('next step', 'Use Graph Nodes or Attack Route Map to reduce clutter before opening node traces.', 'workflow'),
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
    openDetailDrawer('Attack Route Map', 'Topology summary with directed cause/impact actions', items.join(''));
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

function renderEventItem(event, label) {
  const when = event.timestamp || event.time || event.detected_at || event.last_seen;
  const raw = event.raw || {};
  const process = raw.process || {};
  const payload = raw.payload || {};
  const comm = event.comm || process.comm || raw.comm || '--';
  const pid = event.pid || process.pid || raw.pid || '--';
  const type = event.type || raw.type || (raw.rule_id ? 'alert' : 'event');
  const target = event.label || payload.pathname || payload.exe_path || payload.cmdline || raw.message || raw.pattern || raw.path || raw.pathname || raw.rule_id || raw.alert_id || event.id || '';
  const message = type + ' · ' + comm + ' pid ' + pid + (target ? ' · ' + target : '');
  const detail = event.subtype || payload.kind || raw.severity || label;
  const encoded = jsString(JSON.stringify(event || {}));
  return '<div class="alert-item clickable" tabindex="0" role="button" onclick="showEventDetailsJSON(\'' + encoded + '\')" onkeydown="handleCardKey(event, function(){ showEventDetailsJSON(\'' + encoded + '\'); })">' +
    '<span class="alert-sev sev-low">' + escapeHTML(detail) + '</span>' +
    '<span class="alert-msg">' + escapeHTML(message) + '</span>' +
    '<span class="alert-time">' + formatTime(when) + '</span>' +
    '</div>';
}

function eventDetailRows(event) {
  const raw = event.raw || {};
  const process = raw.process || {};
  const payload = raw.payload || {};
  const enrich = raw.enrich || {};
  return [
    renderKVItem('summary', event.type || raw.type || 'event', event.timestamp || raw.timestamp || ''),
    renderKVItem('process', (event.comm || process.comm || raw.comm || '--') + ' pid ' + (event.pid || process.pid || raw.pid || '--'), process.exe_path || ''),
    renderKVItem('payload', JSON.stringify(payload || {}), payload.kind || event.subtype || ''),
    renderKVItem('enrich', JSON.stringify(enrich || {}), raw.schema_version ? ('schema v' + raw.schema_version) : ''),
    renderKVItem('raw', JSON.stringify(raw || event || {}), 'record'),
  ];
}

function renderEventTable(events) {
  return renderDataTable([
    { key: 'time', label: 'Time' },
    { key: 'type', label: 'Type' },
    { key: 'process', label: 'Process' },
    { key: 'target', label: 'Target' },
  ], (events || []).map(event => {
    const raw = event.raw || {};
    const process = raw.process || {};
    const payload = raw.payload || {};
    return {
      time: formatTime(event.timestamp || event.time || event.detected_at || event.last_seen),
      type: event.type || raw.type || 'event',
      process: (event.comm || process.comm || raw.comm || '--') + ' pid ' + (event.pid || process.pid || raw.pid || '--'),
      target: event.label || payload.pathname || payload.exe_path || payload.cmdline || raw.message || raw.pattern || raw.path || raw.pathname || raw.rule_id || raw.alert_id || event.id || '--',
    };
  }), 'No events available for table view');
}

function showEventDetailsJSON(encoded) {
  try {
    const event = JSON.parse(encoded || '{}');
    const title = event.type || (event.raw || {}).type || 'Event Details';
    const subtitle = [event.comm || (event.raw || {}).comm, event.pid || (event.raw || {}).pid, event.timestamp || event.time].filter(Boolean).join(' · ');
    openDetailDrawer(title, subtitle || 'Raw event evidence', eventDetailRows(event).join('') + renderJSONBlock(event));
  } catch (e) {
    setInvestigationLoading('Event detail parse failed: ' + e.message);
  }
}

function alertDetailRows(alert) {
  const traceID = alert.id || alert.node_id || alert.alert_id || '';
  const pattern = alert.pattern || alert.rule_id || alert.headline || '';
  const rows = [
    renderKVItem('status', alert.status || 'open', 'severity ' + formatSeverity(alert.severity || 'info')),
    renderKVItem('rule', pattern || '--', alert.reason || alert.headline || ''),
    renderKVItem('scope', [alert.hostname || alert.host, alert.agent_id, alert.assignee].filter(Boolean).join(' · ') || '--', 'count ' + (alert.count || 1)),
    renderKVItem('time', formatTime(alert.first_seen || alert.created_at) + ' -> ' + formatTime(alert.last_seen || alert.last_notified_at), alert.sla_status || ''),
  ];
  if (traceID) {
    rows.push('<div class="alert-item"><span class="alert-sev sev-medium">trace</span><span class="alert-msg"><span class="graph-cluster-actions">' +
      '<button onclick="openGraphTrace(\'' + jsString(traceID) + '\', \'backward\')">Backward Path</button>' +
      '<button onclick="openGraphTrace(\'' + jsString(traceID) + '\', \'forward\')">Forward Impact</button>' +
      '<button onclick="openTraceViewer(\'' + jsString(traceID) + '\')">Open Trace</button>' +
      '<button onclick="showAlertEvents(\'' + jsString(pattern || traceID) + '\')">Related Events</button>' +
      '</span></span><span class="alert-time">actions</span></div>');
  }
  rows.push(renderJSONBlock(alert));
  return rows;
}

function showAlertDetailsJSON(encoded) {
  try {
    const alert = JSON.parse(encoded || '{}');
    const title = alert.headline || alert.pattern || alert.rule_id || alert.id || 'Alert Details';
    const subtitle = [formatSeverity(alert.severity || 'info'), alert.status || 'open', alert.assignee || 'unassigned'].join(' · ');
    openDetailDrawer(title, subtitle, alertDetailRows(alert).join(''));
  } catch (e) {
    setInvestigationLoading('Alert detail parse failed: ' + e.message);
  }
}

function showAlertDetailsEncoded(encoded) {
  try {
    showAlertDetailsJSON(decodeURIComponent(encoded || '%7B%7D'));
  } catch (e) {
    setInvestigationLoading('Alert detail decode failed: ' + e.message);
  }
}

async function showAlertEvents(pattern) {
  setInvestigationLoading('Searching related alert events...');
  try {
    const data = await fetchJSON('/api/v1/events/search?pattern=' + encodeURIComponent(pattern || '') + '&limit=50');
    const events = data.results || data.events || data.items || [];
    setInvestigationItems(events.slice(0, 20).map(event => renderEventItem(event, 'related')), 'No related events found for this alert');
    openDetailDrawer('Related Events', pattern || 'alert pattern', renderEventTable(events) + renderJSONBlock({ count: events.length, pattern: pattern || '' }));
  } catch (e) {
    setInvestigationLoading('Related event search failed: ' + e.message);
  }
}

async function showRecentEvents() {
  setInvestigationLoading('Loading recent events...');
  try {
    const data = await fetchJSON('/api/v1/events/recent?limit=50');
    const events = data.results || data.events || data.items || [];
    setInvestigationItems(events.slice(0, 20).map(event => renderEventItem(event, 'event')), 'No recent events found');
    openDetailDrawer('Recent Events', events.length + ' event(s)', renderEventTable(events));
  } catch (e) {
    setInvestigationLoading('Recent events unavailable: ' + e.message);
  }
}

async function showDroppedEvents() {
  setInvestigationLoading('Searching dropped event signals...');
  try {
    const data = await fetchJSON('/api/v1/events/search?pattern=dropped&limit=50');
    const events = data.results || data.events || data.items || [];
    setInvestigationItems(events.slice(0, 20).map(event => renderEventItem(event, 'dropped')), 'No dropped event records found');
  } catch (e) {
    setInvestigationLoading('Dropped event search unavailable: ' + e.message);
  }
}

async function showRuntimeDetails(scope) {
  setInvestigationLoading('Loading runtime details...');
  try {
    const status = await fetchJSON('/api/v1/status');
    const health = await fetchJSONAnyStatus('/health');
    const items = [
      '<div class="alert-item"><span class="alert-sev sev-medium">status</span><span class="alert-msg">State: ' + escapeHTML(lastStatus) + ' · Role: ' + escapeHTML(currentRole) + '</span><span class="alert-time">' + escapeHTML(scope) + '</span></div>',
      '<div class="alert-item"><span class="alert-sev sev-low">api</span><span class="alert-msg">Version: ' + escapeHTML(status.version || '--') + ' · Build: ' + escapeHTML(status.build || '--') + '</span><span class="alert-time">status</span></div>',
      '<div class="alert-item"><span class="alert-sev sev-low">health</span><span class="alert-msg">' + escapeHTML(JSON.stringify(health).slice(0, 220)) + '</span><span class="alert-time">health</span></div>',
    ];
    setInvestigationItems(items, 'Runtime details unavailable');
  } catch (e) {
    setInvestigationLoading('Runtime details unavailable: ' + e.message);
  }
}

function investigationReportURL(format) {
  const input = document.getElementById('investigationNodeInput');
  const raw = input && input.value ? input.value.trim() : '';
  const value = raw || '100';
  const params = new URLSearchParams();
  if (/^\d+$/.test(value)) params.set('pid', value); else params.set('node', value);
  params.set('direction', 'backward');
  params.set('depth', '5');
  if (format) params.set('format', format);
  return '/api/v1/investigation/report?' + params.toString();
}

async function showInvestigationReport() {
  setInvestigationLoading('Generating investigation report...');
  try {
    const report = await fetchJSON(investigationReportURL(''));
    const items = [
      renderKVItem('summary', report.risk_summary || '--', report.generated_at),
      renderKVItem('scope', (report.node_count || 0) + ' nodes · ' + (report.edge_count || 0) + ' edges', report.direction),
    ].concat((report.key_observations || []).map(item => renderKVItem('observation', item, 'report')));
    setInvestigationItems(items, 'No investigation report data');
  } catch (e) {
    setInvestigationLoading('Investigation report failed: ' + e.message);
  }
}

async function downloadInvestigationReport() {
  try {
    await downloadWithAuth(investigationReportURL('markdown'), 'providapt-investigation-report.md');
  } catch (e) {
    setInvestigationLoading('Investigation report download failed: ' + e.message);
  }
}

function loadOperationsSummary() {
  const overview = latestOverview || {};
  const fleet = latestFleet || {};
  const workflow = latestWorkflow || {};
  const deliveries = latestDeliveries || {};
  const support = latestSupport || {};
  const upgrade = latestUpgrade || {};
  const workflowSummary = workflow.summary || {};
  const deliverySummary = deliveries.summary || {};
  const totalAgents = overview.total_agents || (overview.agents || []).length || 0;
  const healthyAgents = overview.healthy_agents || 0;
  const openWorkflow = workflowSummary.open || 0;
  const deadLetters = deliverySummary.dead_letter || 0;
  const evidenceReady = support.last_status === 'success' || support.last_archive_path || support.last_bundle_path;
  updateFleetAggregateMetrics(fleet.agents || overview.agents || []);
  updateSidebarPosture();

  document.getElementById('opFleet').textContent = totalAgents ? healthyAgents + '/' + totalAgents : '--';
  document.getElementById('opWorkflow').textContent = openWorkflow;
  document.getElementById('opDelivery').textContent = deadLetters;
  document.getElementById('opEvidence').textContent = evidenceReady ? 'Ready' : 'Pending';

  const items = [
    renderOpsStatusCard('fleet', totalAgents && healthyAgents === totalAgents ? 'sev-low' : 'sev-high', 'control', healthyAgents + ' healthy / ' + totalAgents + ' total agents' + (overview.degraded_agents ? (' · ' + overview.degraded_agents + ' degraded') : '')),
    renderOpsStatusCard('workflow', openWorkflow > 0 ? 'sev-high' : 'sev-low', 'triage', openWorkflow + ' open · ' + (workflowSummary.assigned || 0) + ' assigned · ' + (workflowSummary.suppressed || 0) + ' suppressed'),
    renderOpsStatusCard('delivery', deadLetters > 0 ? 'sev-critical' : 'sev-low', 'notify', (deliverySummary.delivered || 0) + ' delivered · ' + (deliverySummary.retrying || 0) + ' retrying · ' + deadLetters + ' dead letters'),
    renderOpsStatusCard('evidence', evidenceReady ? 'sev-low' : 'sev-medium', 'readiness', 'support bundle ' + (support.last_status || 'pending') + ' · upgrade ' + (upgrade.preflight_ready ? 'preflight ready' : 'not ready')),
  ];
  document.getElementById('operationsSummaryList').innerHTML = items.join('');
}

function renderOpsStatusCard(title, severityClass, stage, detail) {
  return '<div class="ops-status-card">' +
    '<div class="ops-head"><span class="ops-title">' + escapeHTML(title || '--') + '</span><span class="alert-sev ' + escapeHTML(severityClass || 'sev-low') + '">' + escapeHTML(stage || '') + '</span></div>' +
    '<div class="ops-detail">' + escapeHTML(detail || '--') + '</div>' +
    '</div>';
}

function updateSidebarPosture() {
  const overview = latestOverview || {};
  const workflowSummary = (latestWorkflow || {}).summary || {};
  const deliverySummary = (latestDeliveries || {}).summary || {};
  const compliance = latestCompliance || {};
  const totalAgents = overview.total_agents || (overview.agents || []).length || (latestFleet.agents || []).length || 0;
  const readinessRaw = compliance.readiness_score ?? compliance.release_score ?? compliance.score;
  const readiness = readinessRaw == null ? '--' : (String(readinessRaw).includes('%') ? readinessRaw : readinessRaw + '%');
  setText('sidebarAgents', totalAgents || '--');
  setText('sidebarOpenAlerts', workflowSummary.open || 0);
  setText('sidebarDeadLetters', deliverySummary.dead_letter || 0);
  setText('sidebarReadiness', readiness);
}


async function refresh() {
  const now = new Date();
  document.getElementById('refreshInfo').textContent = 'Updated: ' + now.toLocaleTimeString();
  await Promise.all([loadStatus(), loadHealth(), loadControlOverview(), loadSupportBundles(), loadBackups(), loadUpgradeStatus(), loadPolicies(), loadAlertWorkflow(), loadDeliveries(), loadCompliance(), loadGroundTruth()]);
  loadOperationsSummary();
  classifyDashboardButtons();
  normalizeDashboardPanels();
  scheduleDashboardMasonry();
}

window.addEventListener('resize', scheduleDashboardMasonry);

migrateDashboardLayoutStorage();
initializePanelLayout();
installInteractionFeedback();
installProtectedAPILinkHandler();
refresh();
setInterval(refresh, 5000);
