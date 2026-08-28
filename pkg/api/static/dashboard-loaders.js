// Dashboard runtime status, health, and diagnostics loaders.
async function loadStatus() {
  try {
    const data = await fetchJSON('/api/v1/status');
    latestStatus = data || {};
    currentRole = (data.role || 'admin').toLowerCase();
    document.getElementById('roleInfo').textContent = 'Mode: ' + currentRole;
    const deliveryAdmin = currentRole === 'admin';
    const replayAllBtn = document.getElementById('replayAllBtn');
    const createAllTicketsBtn = document.getElementById('createAllTicketsBtn');
    const publishPolicyBtn = document.getElementById('publishPolicyBtn');
    const rollbackPolicyBtn = document.getElementById('rollbackPolicyBtn');
    const downloadPolicyBundleBtn = document.getElementById('downloadPolicyBundleBtn');
    const exportSupportBundleBtn = document.getElementById('exportSupportBundleBtn');
    const downloadSupportBundleBtn = document.getElementById('downloadSupportBundleBtn');
    const createBackupBtn = document.getElementById('createBackupBtn');
    const restoreBackupBtn = document.getElementById('restoreBackupBtn');
    const prepareCutoverBtn = document.getElementById('prepareCutoverBtn');
    const downloadBackupBtn = document.getElementById('downloadBackupBtn');
    const checkUpgradeBtn = document.getElementById('checkUpgradeBtn');
    const preflightUpgradeBtn = document.getElementById('preflightUpgradeBtn');
    const downloadUpgradeBtn = document.getElementById('downloadUpgradeBtn');
    const recordUpgradeBtn = document.getElementById('recordUpgradeBtn');
    if (replayAllBtn) replayAllBtn.disabled = !deliveryAdmin;
    if (createAllTicketsBtn) createAllTicketsBtn.disabled = !deliveryAdmin;
    if (publishPolicyBtn) publishPolicyBtn.disabled = !deliveryAdmin;
    if (rollbackPolicyBtn) rollbackPolicyBtn.disabled = !deliveryAdmin;
    if (downloadPolicyBundleBtn) downloadPolicyBundleBtn.disabled = currentRole === 'analyst';
    if (exportSupportBundleBtn) exportSupportBundleBtn.disabled = !deliveryAdmin;
    if (downloadSupportBundleBtn) downloadSupportBundleBtn.disabled = currentRole === 'analyst';
    if (createBackupBtn) createBackupBtn.disabled = !deliveryAdmin;
    if (restoreBackupBtn) restoreBackupBtn.disabled = !deliveryAdmin;
    if (prepareCutoverBtn) prepareCutoverBtn.disabled = !deliveryAdmin;
    if (downloadBackupBtn) downloadBackupBtn.disabled = !deliveryAdmin;
    if (checkUpgradeBtn) checkUpgradeBtn.disabled = !deliveryAdmin;
    if (preflightUpgradeBtn) preflightUpgradeBtn.disabled = !deliveryAdmin;
    if (downloadUpgradeBtn) downloadUpgradeBtn.disabled = !deliveryAdmin;
    if (recordUpgradeBtn) recordUpgradeBtn.disabled = !deliveryAdmin;
    document.getElementById('mNodes').textContent = data.nodes || 0;
    document.getElementById('mEdges').textContent = data.edges || 0;
    if (data.health) updateStatus(data.health);
    if (data.uptime_seconds) document.getElementById('mUptime').textContent = formatUptime(data.uptime_seconds);
    if (data.memory_bytes) document.getElementById('mMemory').textContent = formatBytes(data.memory_bytes);
    renderDeploymentDiagnostics(data.diagnostics || {});
  } catch(e) {
    document.getElementById('mNodes').textContent = 'err';
    document.getElementById('mEdges').textContent = 'err';
  }
}

function boolState(value, onText, offText) {
  return value ? onText : offText;
}

function renderDeploymentDiagnostics(diag) {
  const apiSecurity = [
    boolState(diag.open_source_control_plane, 'open-source', 'custom'),
    boolState(diag.tls_enabled, 'tls', 'plain')
  ].join(' · ');
  const policyState = diag.policy_enabled ? ('v' + (diag.applied_policy_version || 0)) : 'disabled';
  const storageState = diag.storage_encrypted ? 'encrypted' : 'plain';
  setText('diagAttachment', diag.kernel_attachment_mode || '--');
  setText('diagAPI', apiSecurity);
  setText('diagPolicy', policyState);
  setText('diagStorage', storageState);
  const items = [
    renderKVItem('version', diag.version || '--', 'runtime'),
    renderKVItem('rest api', diag.api_rest || '--', 'open-source control plane'),
    renderKVItem('grpc api', diag.api_grpc || '--', boolState(diag.mtls_enabled, 'mTLS enabled', 'mTLS disabled')),
    renderKVItem('policy bundle', diag.policy_bundle_dir || '--', diag.policy_enabled ? 'enabled' : 'disabled'),
    renderKVItem('control backend', diag.control_plane_state_backend || '--', (diag.control_plane_mode || 'standalone') + ' · ' + (diag.control_plane_role || 'auto')),
    renderKVItem('storage', diag.output_dir || '--', boolState(diag.storage_encrypted, 'encrypted', 'not encrypted')),
  ];
  const list = document.getElementById('deploymentDiagnosticsList');
  if (list) {
    list.innerHTML = items.join('');
  }
}

function showDeploymentDiagnostics(scope) {
  const diag = (latestStatus && latestStatus.diagnostics) || {};
  const rows = [];
  if (scope === 'attachment') {
    rows.push(renderKVItem('kernel mode', diag.kernel_attachment_mode || '--', 'active attachment'));
    rows.push(renderKVItem('version', diag.version || '--', 'daemon build'));
  } else if (scope === 'api') {
    rows.push(renderKVItem('rest api', diag.api_rest || '--', 'open-source control plane'));
    rows.push(renderKVItem('grpc api', diag.api_grpc || '--', boolState(diag.mtls_enabled, 'mTLS enabled', 'mTLS disabled')));
    rows.push(renderKVItem('tls', boolState(diag.tls_enabled, 'enabled', 'disabled'), 'transport'));
  } else if (scope === 'policy') {
    rows.push(renderKVItem('policy sync', diag.policy_enabled ? 'enabled' : 'disabled', 'runtime'));
    rows.push(renderKVItem('endpoint', diag.policy_endpoint || '--', 'control plane'));
    rows.push(renderKVItem('bundle dir', diag.policy_bundle_dir || '--', 'local cache'));
    rows.push(renderKVItem('applied version', diag.applied_policy_version || 0, 'agent state'));
  } else if (scope === 'storage') {
    rows.push(renderKVItem('output dir', diag.output_dir || '--', 'data path'));
    rows.push(renderKVItem('encryption', boolState(diag.storage_encrypted, 'enabled', 'disabled'), boolState(diag.storage_key_configured, 'key configured', 'key missing')));
    rows.push(renderKVItem('state backend', diag.control_plane_state_backend || '--', 'control plane'));
    rows.push(renderKVItem('support bundle', diag.support_bundle_enabled ? 'available' : 'disabled', 'evidence export'));
  }
  setInvestigationItems(rows, 'No deployment diagnostics available');
}

async function loadHealth() {
  try {
    const h = await fetchJSON('/health');
    updateStatus(h.status);
    if (h.uptime_seconds) document.getElementById('mUptime').textContent = formatUptime(h.uptime_seconds);
    if (h.memory_bytes) document.getElementById('mMemory').textContent = formatBytes(h.memory_bytes);
    if (h.events_ingested != null) document.getElementById('mEvents').textContent = h.events_ingested.toLocaleString();
    if (h.events_dropped != null) document.getElementById('mDropped').textContent = h.events_dropped.toLocaleString();
  } catch(e) { /* ignore */ }
}
