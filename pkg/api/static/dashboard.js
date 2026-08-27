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

async function loadGroundTruth() {
  const status = document.getElementById('groundTruthStatus');
  if (status) status.textContent = 'Loading server ground truth records...';
  try {
    const data = await fetchJSON('/api/v1/evaluation/ground-truth?limit=500');
    latestGroundTruth = data || { records: [], phases: {}, files: [] };
    groundTruthFilter = 'all';
    renderGroundTruth();
  } catch (e) {
    latestGroundTruth = { records: [], phases: {}, files: [] };
    if (isAuthzError(e)) {
      renderGroundTruth('Server ground truth requires local API access. Use Load Local JSONL for local evidence files.');
      return;
    }
    renderGroundTruth('Server ground truth unavailable: ' + e.message + '. Use Load Local JSONL for local evidence files.');
  }
}

function updateGroundTruthFileName() {
  const input = document.getElementById('groundTruthFile');
  const name = document.getElementById('groundTruthFileName');
  const file = input && input.files && input.files[0];
  if (name) {
    name.textContent = file ? (file.name + ' · ' + formatBytes(file.size || 0)) : 'No local file selected';
  }
}

async function loadGroundTruthFromFile() {
  const input = document.getElementById('groundTruthFile');
  const file = input && input.files && input.files[0];
  if (!file) {
    renderGroundTruth('Choose a .jsonl ground truth file first.');
    return;
  }
  updateGroundTruthFileName();
  const text = await file.text();
  const records = parseGroundTruthJSONL(text, file.name);
  latestGroundTruth = summarizeGroundTruthRecords(records, [file.name]);
  groundTruthFilter = 'all';
  renderGroundTruth();
}

function parseGroundTruthJSONL(text, sourceFile) {
  return String(text || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => {
    try {
      const record = JSON.parse(line);
      record.source_file = record.source_file || sourceFile;
      return record;
    } catch (e) {
      return null;
    }
  }).filter(Boolean);
}

function summarizeGroundTruthRecords(records, files) {
  const phases = {};
  let malicious = 0;
  let benign = 0;
  records.forEach(record => {
    if (record.malicious) malicious += 1; else benign += 1;
    const phase = record.phase || 'unknown';
    phases[phase] = (phases[phase] || 0) + 1;
  });
  return {
    updated_at: new Date().toISOString(),
    run_id: records[0] ? (records[0].run_id || '') : '',
    files: files || [],
    total: records.length,
    malicious: malicious,
    benign: benign,
    phases: phases,
    records: records,
  };
}

function normalizedGroundTruthLabel(record, split) {
  const malicious = !!record.malicious;
  return {
    schema: 'providapt.evaluation_dataset.v1',
    dataset_split: split || 'unsplit',
    label: malicious ? 'malicious' : 'benign',
    malicious: malicious,
    run_id: record.run_id || '',
    source_file: record.source_file || '',
    category: record.category || record.phase || '',
    phase: record.phase || '',
    step_index: record.step_index || 0,
    step_id: record.step_id || '',
    step_name: record.step_name || '',
    tactic_id: record.tactic_id || record.tactic || 'benign',
    tactic_name: record.tactic_name || '',
    technique_id: record.technique_id || 'benign',
    technique_name: record.technique_name || '',
    mitre_url: record.mitre_url || '',
    expected_event: record.expected_event || '',
    expected_relation: record.expected_relation || '',
    actor: record.actor || '',
    object: record.object || '',
    command: record.command || '',
  };
}

function stableGroundTruthBucket(record) {
  const key = [record.run_id || '', record.step_id || '', record.step_index || '', record.command || ''].join('|');
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    hash = ((hash << 5) - hash + key.charCodeAt(i)) | 0;
  }
  return Math.abs(hash % 100);
}

function groundTruthDatasetRecords() {
  const records = (latestGroundTruth.records || []).slice().sort((a, b) =>
    String(a.run_id || '').localeCompare(String(b.run_id || '')) ||
    Number(a.step_index || 0) - Number(b.step_index || 0) ||
    String(a.step_id || '').localeCompare(String(b.step_id || ''))
  );
  return records.map(record => normalizedGroundTruthLabel(record, stableGroundTruthBucket(record) < 80 ? 'train' : 'test'));
}

function buildGroundTruthCoverage() {
  const records = latestGroundTruth.records || [];
  const correlationRows = (latestGroundTruthCorrelation.records || []);
  const byTactic = {};
  const byCategory = {};
  const byRun = {};
  const correlation = {};
  const hasCorrelation = correlationRows.length > 0;
  correlationRows.forEach(row => {
    const truth = row.ground_truth || {};
    const key = [truth.run_id || '', truth.step_id || '', truth.step_index || '', truth.command || ''].join('|');
    correlation[key] = row.status || 'unknown';
  });
  let detected = 0;
  records.forEach(record => {
    const key = [record.run_id || '', record.step_id || '', record.step_index || '', record.command || ''].join('|');
    const status = correlation[key] || 'simulated';
    const bucket = status === 'matched' ? 'detected' : (hasCorrelation ? 'missed' : 'simulated');
    if (status === 'matched') detected += 1;
    [
      [byTactic, record.tactic_id || record.tactic || 'benign'],
      [byCategory, record.category || record.phase || 'unknown'],
      [byRun, record.run_id || 'unknown'],
    ].forEach(pair => {
      const group = pair[0];
      const name = pair[1];
      group[name] = group[name] || { total: 0, malicious: 0, benign: 0, detected: 0, missed: 0, simulated: 0 };
      group[name].total += 1;
      if (record.malicious) group[name].malicious += 1; else group[name].benign += 1;
      group[name][bucket] += 1;
    });
  });
  const malicious = records.filter(record => record.malicious).length;
  return {
    schema: 'providapt.attack_coverage.v1',
    generated_at: new Date().toISOString(),
    total: records.length,
    malicious: malicious,
    benign: records.length - malicious,
    detected: detected,
    coverage_percent: malicious ? Number((detected / malicious * 100).toFixed(2)) : 0,
    correlation_status: hasCorrelation ? 'merged' : 'not_provided',
    by_tactic: byTactic,
    by_category: byCategory,
    by_run: byRun,
  };
}

function downloadTextFile(fileName, text, type) {
  const blob = new Blob([text], { type: type || 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function downloadGroundTruthDataset(kind) {
  const labels = groundTruthDatasetRecords();
  if (labels.length === 0) {
    setInvestigationLoading('No ground truth records loaded for dataset export.');
    return;
  }
  const coverage = buildGroundTruthCoverage();
  const manifest = {
    schema: 'providapt.evaluation_dataset.v1',
    generated_at: new Date().toISOString(),
    record_count: labels.length,
    train_count: labels.filter(item => item.dataset_split === 'train').length,
    test_count: labels.filter(item => item.dataset_split === 'test').length,
    files: {
      labels: 'providapt-labels.jsonl',
      coverage: 'providapt-coverage.json',
      manifest: 'providapt-dataset-manifest.json',
    },
    source_files: latestGroundTruth.files || [],
  };
  if (kind === 'manifest') {
    downloadTextFile('providapt-dataset-manifest.json', JSON.stringify(manifest, null, 2) + '\n');
  } else if (kind === 'coverage') {
    downloadTextFile('providapt-coverage.json', JSON.stringify(coverage, null, 2) + '\n');
  } else {
    downloadTextFile('providapt-labels.jsonl', labels.map(item => JSON.stringify(item)).join('\n') + '\n', 'application/x-ndjson');
  }
  setInvestigationItems([
    renderKVItem('dataset export', labels.length + ' labels', manifest.train_count + ' train · ' + manifest.test_count + ' test'),
    renderKVItem('coverage', coverage.coverage_percent + '%', coverage.correlation_status),
  ], 'Dataset export prepared');
}

function renderGroundTruth(message) {
  const data = latestGroundTruth || {};
  const records = data.records || [];
  const filtered = records.filter(record => {
    if (groundTruthFilter === 'malicious') return !!record.malicious;
    if (groundTruthFilter === 'benign') return !record.malicious;
    if (groundTruthFilter && groundTruthFilter !== 'all') return String(record.phase || '') === groundTruthFilter;
    return true;
  });
  setText('gtTotal', data.total != null ? data.total : records.length);
  setText('gtMalicious', data.malicious != null ? data.malicious : records.filter(r => r.malicious).length);
  setText('gtBenign', data.benign != null ? data.benign : records.filter(r => !r.malicious).length);
  setText('gtRunID', truncateText(data.run_id || '--', 16));
  renderGroundTruthPhases(data.phases || {});
  const status = document.getElementById('groundTruthStatus');
  if (status) {
    const files = (data.files || []).join(', ');
    status.textContent = message || (records.length
      ? 'Loaded ' + records.length + ' record(s)' + (data.run_id ? ' from run ' + data.run_id : '') + (files ? ' · ' + files : '')
      : 'No server ground truth found. Upload a local JSONL file or place records under /var/log/providapt/ground-truth/.');
  }
  const list = document.getElementById('groundTruthList');
  if (!list) return;
  if (filtered.length === 0) {
    list.innerHTML = '<div class="loading">No ground truth records match this filter.</div>';
    return;
  }
  list.innerHTML = filtered.slice(0, 80).map(renderGroundTruthRecord).join('');
}

function showGroundTruthCoverage() {
  const coverage = buildGroundTruthCoverage();
  const rows = [
    renderKVItem('records', coverage.total, coverage.malicious + ' malicious · ' + coverage.benign + ' benign'),
    renderKVItem('coverage', coverage.coverage_percent + '%', coverage.detected + ' detected · ' + coverage.correlation_status),
  ];
  Object.entries(coverage.by_tactic || {}).sort((a, b) => b[1].total - a[1].total).slice(0, 12).forEach(([tactic, row]) => {
    rows.push(renderKVItem(tactic, row.total + ' records', (row.detected || 0) + ' detected · ' + (row.missed || 0) + ' missed · ' + (row.simulated || 0) + ' simulated'));
  });
  setInvestigationItems(rows, 'Load ground truth records before viewing coverage.');
  const status = document.getElementById('groundTruthStatus');
  if (status) {
    status.textContent = 'ATT&CK coverage summary · ' + coverage.total + ' records · ' + coverage.coverage_percent + '% detected';
  }
}

function showMitreAttackMatrix() {
  const coverage = buildGroundTruthCoverage();
  const tactics = Object.entries(coverage.by_tactic || {}).sort((a, b) => b[1].total - a[1].total);
  const categories = Object.entries(coverage.by_category || {}).sort((a, b) => b[1].total - a[1].total);
  const cards = '<div class="matrix-grid">' + [
    '<div class="matrix-card"><div class="label">Records</div><div class="value">' + coverage.total + '</div><div class="sub">' + coverage.malicious + ' malicious · ' + coverage.benign + ' benign</div></div>',
    '<div class="matrix-card"><div class="label">Detected</div><div class="value">' + coverage.coverage_percent + '%</div><div class="sub">' + coverage.detected + ' detected · ' + (coverage.malicious - coverage.detected) + ' remaining</div></div>',
    '<div class="matrix-card"><div class="label">Correlation</div><div class="value">' + escapeHTML(coverage.correlation_status) + '</div><div class="sub">ground truth to alerts/events</div></div>',
  ].join('') + '</div>';
  const tacticTable = renderDataTable([
    { key: 'tactic', label: 'ATT&CK Tactic' },
    { key: 'total', label: 'Records' },
    { key: 'detected', label: 'Detected' },
    { key: 'missed', label: 'Missed' },
    { key: 'simulated', label: 'Simulated' },
  ], tactics.map(([name, row]) => Object.assign({ tactic: name }, row)), 'No MITRE tactic records loaded');
  const categoryTable = renderDataTable([
    { key: 'category', label: 'Technique / Category' },
    { key: 'total', label: 'Records' },
    { key: 'malicious', label: 'Malicious' },
    { key: 'detected', label: 'Detected' },
    { key: 'missed', label: 'Missed' },
  ], categories.slice(0, 40).map(([name, row]) => Object.assign({ category: name }, row)), 'No MITRE technique records loaded');
  openDetailDrawer('MITRE ATT&CK Matrix', 'Coverage by tactic and technique/category', cards + tacticTable + categoryTable);
  setInvestigationItems(tactics.slice(0, 12).map(([name, row]) => renderKVItem(name, row.total + ' records', row.detected + ' detected · ' + row.missed + ' missed')), 'No ATT&CK coverage loaded');
}

function showDetectionQualityDashboard() {
  const alertMetrics = computeAlertQuality(latestWorkflow.alerts || []);
  const coverage = buildGroundTruthCoverage();
  const actionable = alertMetrics.true_positive + alertMetrics.false_positive + alertMetrics.benign;
  const recall = coverage.malicious ? Number((coverage.detected * 100 / coverage.malicious).toFixed(1)) : 0;
  const precision = alertMetrics.actionable_precision_percent || 0;
  const f1 = precision + recall ? Number((2 * precision * recall / (precision + recall)).toFixed(1)) : 0;
  const rows = [
    { metric: 'Precision', value: precision + '%', detail: alertMetrics.true_positive + ' TP / ' + actionable + ' reviewed actionable alerts' },
    { metric: 'Recall', value: recall + '%', detail: coverage.detected + ' detected / ' + coverage.malicious + ' malicious ground-truth rows' },
    { metric: 'F1', value: f1 + '%', detail: 'harmonic mean of precision and recall' },
    { metric: 'Review Coverage', value: alertMetrics.review_coverage_percent + '%', detail: alertMetrics.reviewed_alerts + ' reviewed / ' + alertMetrics.total_alerts + ' alerts' },
    { metric: 'Duplicate Rate', value: alertMetrics.duplicate_percent + '%', detail: alertMetrics.duplicate + ' duplicate alerts' },
  ];
  const cards = '<div class="matrix-grid">' + rows.slice(0, 4).map(row => '<div class="matrix-card"><div class="label">' + escapeHTML(row.metric) + '</div><div class="value">' + escapeHTML(row.value) + '</div><div class="sub">' + escapeHTML(row.detail) + '</div></div>').join('') + '</div>';
  const table = renderDataTable([
    { key: 'metric', label: 'Metric' },
    { key: 'value', label: 'Value' },
    { key: 'detail', label: 'Evidence' },
  ], rows, 'No quality metrics available');
  openDetailDrawer('Detection Quality', 'Precision, recall, F1, review coverage, and duplicate rate', cards + table + renderJSONBlock({ alert_quality: alertMetrics, ground_truth_coverage: coverage }));
  setInvestigationItems(rows.map(row => renderKVItem(row.metric, row.value, row.detail)), 'No detection quality metrics available');
}

function renderGroundTruthPhases(phases) {
  const grid = document.getElementById('groundTruthPhaseGrid');
  if (!grid) return;
  const entries = Object.entries(phases || {}).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    grid.innerHTML = '';
    return;
  }
  grid.innerHTML = entries.map(([phase, count]) =>
    '<div class="mini-card clickable" data-ground-truth-phase="' + escapeHTML(phase) + '">' +
    '<div class="value">' + count + '</div><div class="label">' + escapeHTML(phase) + '</div></div>'
  ).join('');
  grid.querySelectorAll('[data-ground-truth-phase]').forEach(item => {
    item.onclick = () => filterGroundTruth(item.getAttribute('data-ground-truth-phase'));
  });
}

function renderGroundTruthRecord(record) {
  const kind = record.malicious ? 'malicious' : 'benign';
  const object = record.object || '';
  const step = record.step_id || (record.step_index ? 'step-' + String(record.step_index).padStart(2, '0') : '');
  const category = record.category || record.phase || 'unknown';
  const tactic = record.tactic_name || record.tactic || record.phase || 'unknown';
  const technique = record.technique_name || record.technique || '';
  const nodeID = groundTruthNodeID(record);
  const traceLink = nodeID
    ? '<button class="secondary" onclick="openTraceViewer(\'' + jsString(nodeID) + '\')">Open Trace</button>'
    : '';
  const mitreLink = record.mitre_url
    ? '<a href="' + escapeHTML(record.mitre_url) + '" target="_blank" rel="noreferrer">MITRE</a>'
    : '';
  const eventLink = record.expected_event || record.command || record.actor
    ? '<a href="/api/v1/events/search?pattern=' + encodeURIComponent(record.actor || record.expected_event || record.command || '') + '&limit=50" target="_blank" rel="noreferrer">Events</a>'
    : '';
  return '<div class="alert-item truth-record">' +
    '<span class="alert-sev sev-' + (record.malicious ? 'high' : 'low') + '">' + escapeHTML(record.phase || 'unknown') + '</span>' +
    '<span class="alert-msg"><span class="truth-badge ' + kind + '">' + kind + '</span>' +
    escapeHTML((step ? step + ' · ' : '') + category + ' · ' + (record.step_name || record.command || record.technique || 'ground truth record')) +
    '<br><code>' + escapeHTML(tactic + (technique ? ' / ' + technique : '') + ' · ' + (record.actor || '?') + ' -> ' + object + ' · ' + (record.expected_event || '?') + ' · ' + (record.expected_relation || '?')) + '</code></span>' +
    '<span class="trace-actions">' + traceLink + eventLink + mitreLink + '</span>' +
    '</div>';
}

function filterGroundTruth(filter) {
  groundTruthFilter = filter || 'all';
  renderGroundTruth();
  setInvestigationItems((latestGroundTruth.records || []).filter(record => {
    if (groundTruthFilter === 'malicious') return !!record.malicious;
    if (groundTruthFilter === 'benign') return !record.malicious;
    if (groundTruthFilter !== 'all') return String(record.phase || '') === groundTruthFilter;
    return true;
  }).slice(0, 20).map(record => renderKVItem(record.phase || 'ground truth', record.command || record.technique || '', (record.actor || '?') + ' -> ' + (record.object || '?'))), 'No ground truth records loaded');
}

async function showGroundTruthCorrelation() {
  try {
    const data = await fetchJSON('/api/v1/evaluation/correlation?limit=200');
    latestGroundTruthCorrelation = data || { records: [] };
    renderGroundTruthCorrelation(data);
    return;
  } catch (e) {
    if (isAuthzError(e)) {
      setInvestigationLoading('Server correlation requires local API access; using browser-loaded ground truth when available.');
      renderLocalGroundTruthCorrelation();
      return;
    }
    setInvestigationLoading('Server correlation unavailable; using browser-loaded ground truth: ' + e.message);
  }
  renderLocalGroundTruthCorrelation();
}

function renderGroundTruthCorrelation(data) {
  const records = (data && data.records) || [];
  const rows = [
    renderKVItem('coverage', formatNumber(data.coverage_percent || 0) + '%', (data.matched_records || 0) + '/' + (data.total || 0) + ' matched'),
    renderKVItem('event matches', data.event_matches || 0, 'records with raw event evidence'),
    renderKVItem('alert matches', data.alert_matches || 0, 'records with workflow alert evidence'),
    renderKVItem('traceable records', data.traceable || 0, 'records with p:<pid> trace links'),
  ];
  records.slice(0, 24).forEach(row => {
    const truth = row.ground_truth || {};
    const label = (truth.phase || 'ground truth') + (truth.malicious ? ' · malicious' : ' · benign');
    const value = row.status || 'unknown';
    const matches = (row.event_matches || []).length + ' events, ' + (row.alert_matches || []).length + ' alerts';
    const trace = row.trace_node ? ' · trace ' + row.trace_node : '';
    rows.push(renderKVItem(label, value, matches + trace));
  });
  setInvestigationItems(rows, 'No ground truth correlation data available');
  const status = document.getElementById('groundTruthStatus');
  if (status) {
    status.textContent = 'Correlation coverage ' + formatNumber(data.coverage_percent || 0) + '% · ' + (data.matched_records || 0) + '/' + (data.total || 0) + ' records matched';
  }
}

function renderLocalGroundTruthCorrelation() {
  const records = latestGroundTruth.records || [];
  const alerts = latestWorkflow.alerts || [];
  const rows = [
    renderKVItem('ground truth records', records.length, (latestGroundTruth.run_id || 'no run id')),
    renderKVItem('loaded alerts', alerts.length, alerts.length ? 'workflow available' : 'no workflow alerts loaded'),
  ];
  records.filter(record => record.malicious).slice(0, 10).forEach(record => {
    const hit = alerts.find(alert => alertMatchesTruth(alert, record));
    rows.push(renderKVItem(record.phase || 'malicious', hit ? 'matched alert ' + hit.id : 'no direct alert match', record.actor + ' -> ' + record.object));
  });
  setInvestigationItems(rows, 'Load ground truth and alerts before correlating.');
}

function alertMatchesTruth(alert, record) {
  const haystack = [alert.id, alert.pattern, alert.headline, alert.reason].join(' ').toLowerCase();
  return [record.actor, record.object, record.expected_event, record.phase]
    .filter(Boolean)
    .some(value => haystack.indexOf(String(value).toLowerCase()) >= 0);
}

function groundTruthNodeID(record) {
  const object = String(record.object || '');
  if (/^p:\d+$/.test(object)) return object;
  const pidMatch = object.match(/^pid:(\d+)$/);
  if (pidMatch) return 'p:' + pidMatch[1];
  return '';
}

async function loadCompliance() {
  try {
    const data = await fetchJSON('/api/v1/control/compliance');
    latestCompliance = data;
    const siem = data.siem || {};
    const approvals = data.approvals || {};
    setText('cAuditEntries', data.audit_entries || 0);
    setText('cRetention', data.retention_days ? data.retention_days + 'd' : '--');
    setText('cSIEM', siem.enabled ? ((siem.provider || 'generic') + ':' + (siem.last_status || 'Enabled')) : 'Disabled');
    setText('cApprovals', (approvals.pending || []).length);
    showComplianceDetails('audit');
  } catch (e) {
    document.getElementById('complianceDetails').innerHTML = '<div class="loading">Compliance state unavailable</div>';
  }
}

function showComplianceDetails(scope) {
  const data = latestCompliance || {};
  const siem = data.siem || {};
  const approvals = data.approvals || {};
  let items = [];
  if (scope === 'siem') {
    items = [
      renderKVItem('enabled', siem.enabled ? 'yes' : 'no', siem.format || 'json'),
      renderKVItem('provider', siem.provider || 'generic', 'native connector'),
      renderKVItem('endpoint', siem.endpoint || siem.outbox_path || '--', siem.min_severity || 'INFO'),
      renderKVItem('last status', siem.last_status || '--', formatTime(siem.last_forwarded_at)),
      renderKVItem('last error', siem.last_error || '--', 'diagnostic'),
    ];
  } else if (scope === 'approvals') {
    const pending = approvals.pending || [];
    items = pending.length
      ? pending.map(item => renderApprovalItem(item))
      : [renderKVItem('pending', 'no pending approvals', 'approval')];
    (approvals.history || []).filter(item => item.status !== 'pending').slice(0, 8).forEach(item => {
      items.push(renderKVItem(item.id || 'approval', (item.action || '--') + ' · ' + (item.status || '--') + (item.used_by ? (' · used by ' + item.used_by) : ''), formatTime(item.used_at || item.approved_at || item.requested_at)));
    });
  } else if (scope === 'retention') {
    items = [
      renderKVItem('retention', (data.retention_days || 0) + ' days', 'policy'),
      renderKVItem('max entries', data.max_audit_entries || 0, 'memory window'),
      renderKVItem('oldest allowed', data.oldest_allowed_at || '--', 'cutoff'),
      renderKVItem('recommendations', (data.recommended_actions || []).join('; ') || 'none', 'readiness'),
    ];
  } else {
    items = [
      renderKVItem('audit entries', data.audit_entries || 0, 'current window'),
      renderKVItem('readiness', (data.readiness_score || 0) + '/100', data.readiness_grade || '--'),
      renderKVItem('tenant', data.tenant || 'all', 'scope'),
      renderKVItem('oldest audit', data.audit_oldest_at || '--', 'oldest'),
      renderKVItem('newest audit', data.audit_newest_at || '--', 'newest'),
      renderKVItem('last archive', data.last_archive_path || '--', (data.last_archived_count || 0) + ' archived'),
      renderKVItem('last export', data.last_export_path || '--', 'evidence'),
      renderKVItem('last report', data.last_report_path || '--', 'report'),
    ];
  }
  document.getElementById('complianceDetails').innerHTML = items.join('');
}

function showReleaseReadiness() {
  const data = latestCompliance || {};
  const support = latestSupport || {};
  const backup = latestBackup || {};
  const policies = latestPolicies || {};
  const upgrade = latestUpgrade || {};
  const checks = [
    ['compliance', (data.readiness_score || 0) + '/100 · ' + (data.readiness_grade || '--'), (data.readiness_score || 0) >= 80],
    ['support bundle', support.last_status || 'not exported', support.last_status === 'success' || support.last_archive_path],
    ['backup', backup.last_backup_path || 'not created', Boolean(backup.last_backup_path)],
    ['policy bundle', policies.current && policies.current.bundle_sha256 ? policies.current.bundle_sha256.slice(0, 12) : 'missing', Boolean(policies.current && policies.current.bundle_sha256)],
    ['upgrade preflight', upgrade.preflight_ready ? 'ready' : 'not ready', Boolean(upgrade.preflight_ready)],
  ];
  const items = checks.map(item => renderKVItem(item[0], item[1], item[2] ? 'pass' : 'action required'));
  document.getElementById('complianceDetails').innerHTML = items.join('');
}

function buildExecutiveReport() {
  const alertMetrics = computeAlertQuality(latestWorkflow.alerts || []);
  const coverage = buildGroundTruthCoverage();
  const overview = latestOverview || {};
  const compliance = latestCompliance || {};
  const deliverySummary = (latestDeliveries || {}).summary || {};
  return {
    schema: 'providapt.executive_report.v1',
    generated_at: new Date().toISOString(),
    fleet: {
      total_agents: overview.total_agents || (overview.agents || []).length || 0,
      healthy_agents: overview.healthy_agents || 0,
      degraded_agents: overview.degraded_agents || 0,
    },
    detection: {
      alert_quality: alertMetrics,
      mitre_coverage: coverage,
      open_alerts: ((latestWorkflow || {}).summary || {}).open || 0,
    },
    evidence: {
      support_bundle_status: (latestSupport || {}).last_status || '',
      backup_status: (latestBackup || {}).last_status || '',
      delivery_dead_letters: deliverySummary.dead_letter || 0,
    },
    open_source_readiness: {
      readiness_score: compliance.readiness_score || 0,
      readiness_grade: compliance.readiness_grade || '',
      siem_enabled: Boolean((compliance.siem || {}).enabled),
      pending_approvals: (((compliance.approvals || {}).pending) || []).length,
    },
  };
}

function downloadExecutiveReport() {
  const report = buildExecutiveReport();
  downloadTextFile('providapt-executive-report.json', JSON.stringify(report, null, 2) + '\n');
  openDetailDrawer('Executive Report', 'Open-source readiness, detection quality, fleet, and evidence summary', renderJSONBlock(report));
}

async function showAuditSearch() {
  const params = new URLSearchParams({ category: 'admin', limit: '25' });
  const sources = ['supportbundle', 'backup', 'policy', 'upgrade', 'delivery'];
  const items = [];
  for (const source of sources) {
    try {
      const data = await fetchJSON('/api/v1/control/audit?' + new URLSearchParams({ category: 'admin', source: source, limit: '5' }).toString());
      const entries = (data && data.entries) || [];
      items.push(renderKVItem(source, entries.length + ' recent audit entry(s)', 'filter source'));
    } catch (e) {
      items.push(renderKVItem(source, 'audit search unavailable: ' + e.message, 'error'));
    }
  }
  items.push(renderKVItem('download', '/api/v1/control/audit?' + params.toString(), 'CSV/JSON endpoint'));
  document.getElementById('complianceDetails').innerHTML = items.join('');
  openDetailDrawer('Audit Search', 'Administrative audit sources and export endpoint', items.join(''));
}

function renderApprovalItem(item) {
  const id = jsString(item.id || '');
  const actions = currentRole === 'admin'
    ? "<span class=\"delivery-inline-actions\"><button onclick=\"runApprovalAction('approve', 'REPLACE_ID')\">Approve</button><button class=\"secondary\" onclick=\"runApprovalAction('reject', 'REPLACE_ID')\">Reject</button></span>".replace(/REPLACE_ID/g, id)
    : '';
  return '<div class="alert-item">' +
    '<span class="alert-sev sev-medium">' + escapeHTML(item.id || 'approval') + '</span>' +
    '<span class="alert-msg">' + escapeHTML(item.action || '--') + ' · ' + escapeHTML(item.status || '--') + (item.requested_by ? (' · ' + escapeHTML(item.requested_by)) : '') + (item.expires_at ? (' · expires ' + escapeHTML(formatTime(item.expires_at))) : '') + actions + '</span>' +
    '<span class="alert-time">' + escapeHTML(formatTime(item.requested_at)) + '</span>' +
    '</div>';
}

async function runApprovalAction(action, approvalID) {
  await runComplianceAction(action, '', approvalID);
  showComplianceDetails('approvals');
}

async function runComplianceAction(action, format, approvalID) {
  if (!requireAdminAction('Compliance action')) {
    return;
  }
  const status = document.getElementById('complianceActionStatus');
  status.textContent = 'Running ' + action + '...';
  try {
    const data = await postJSON('/api/v1/control/compliance', { action: action, format: format || 'csv', approval_id: approvalID || '', note: 'dashboard ' + action });
    status.textContent = data.message || 'Compliance action completed';
    if (action === 'test_siem') {
      const siem = data.siem || {};
      await loadCompliance();
      document.getElementById('complianceDetails').innerHTML = [
        renderKVItem('siem test', data.status || data.message || 'completed', siem.provider || 'provider'),
        renderKVItem('destination', siem.endpoint || siem.outbox_path || '--', siem.format || format || 'json'),
        renderKVItem('diagnostic', data.error || siem.last_error || 'no error returned', siem.last_status || 'check connector'),
      ].join('');
      return;
    }
    if (data.artifacts) {
      document.getElementById('complianceDetails').innerHTML = Object.keys(data.artifacts).sort().map((key) => renderKVItem(key, data.artifacts[key], 'report artifact')).join('');
    } else if (data.path) {
      document.getElementById('complianceDetails').innerHTML = renderKVItem('path', data.path, format || 'artifact');
    }
    await loadCompliance();
  } catch (e) {
    status.textContent = 'Compliance action failed: ' + e.message;
  }
}

async function loadDeliveries() {
  try {
    const data = await fetchJSON('/api/v1/control/deliveries');
    latestDeliveries = data;
    const summary = data.summary || {};
    setText('dDelivered', summary.delivered || 0);
    setText('dRetrying', summary.retrying || 0);
    setText('dDeadLetters', summary.dead_letter || 0);
    setText('dDeadLettersDetail', summary.dead_letter || 0);
    setText('dRecentCount', (data.recent || []).length);
    const list = document.getElementById('deliveryList');
    const historyList = document.getElementById('deliveryHistoryList');
    const deadLetters = data.dead_letters || [];
    const recent = data.recent || [];
    const history = data.history || [];
    const allDeliveries = recent.concat(deadLetters);
    const channels = countBy(allDeliveries, item => item.notifier);
    const ticketed = allDeliveries.filter(item => item.ticket_key).length;
    const errorTypes = countBy(allDeliveries.filter(item => item.error), item => String(item.error || '').split(':')[0].slice(0, 40));
    setText('dChannels', channels.length);
    setText('dTickets', ticketed);
    setText('dErrors', errorTypes.length);
    const source = deadLetters.length > 0 ? deadLetters : recent;
    if (source.length === 0) {
      list.innerHTML = '<div class="loading">No delivery attempts yet. Configure notifiers or SIEM delivery, then use Test SIEM or Replay All.</div>';
    } else {
      list.innerHTML = source.slice(0, 8).map(item => {
        const ticket = item.ticket_key
          ? '<a class="ticket-link" href="' + (item.ticket_url || '#') + '" target="_blank" rel="noreferrer">' + item.ticket_key + '</a>'
          : '';
        const actions = currentRole === 'admin' && item.status === 'dead_letter'
          ? '<span class="delivery-inline-actions">' +
            "<button onclick=\"prepareDeliveryAction('replay', '" + (item.id || '') + "')\">Replay</button>" +
            "<button class=\"secondary\" onclick=\"prepareDeliveryAction('create_ticket', '" + (item.id || '') + "')\">Create Ticket</button>" +
            '</span>'
          : '';
        return '<div class="alert-item">' +
          '<span class="alert-sev ' + (item.status === 'dead_letter' ? 'sev-critical' : 'sev-medium') + '">' + (item.status || 'delivered') + '</span>' +
          '<span class="alert-msg">' + (item.notifier || 'notifier') + ' · ' + (item.pattern || 'alert') + ' · attempt ' + (item.attempt || 1) + '/' + (item.max_attempts || 1) + (item.error ? (' · ' + item.error) : '') + (ticket ? (' · ' + ticket) : '') + '</span>' +
          '<span class="alert-time">' + formatTime(item.last_attempt_at) + '</span>' +
          actions +
          '</div>';
      }).join('');
    }
    if (historyList) {
      if (history.length === 0) {
        historyList.innerHTML = '<div class="loading">No delivery actions recorded yet</div>';
      } else {
        historyList.innerHTML = history.slice(0, 10).map(item => {
          const ticket = item.ticket_key
            ? '<a class="ticket-link" href="' + (item.ticket_url || '#') + '" target="_blank" rel="noreferrer">' + item.ticket_key + '</a>'
            : '';
          const actor = item.actor ? ' · ' + item.actor : '';
          const note = item.note ? ' · note: ' + item.note : '';
          const counts = item.processed
            ? ' · ' + (item.succeeded || 0) + ' ok / ' + (item.skipped || 0) + ' skipped / ' + (item.failed || 0) + ' failed'
            : '';
          return '<div class="alert-item">' +
            '<span class="alert-sev ' + (String(item.status || '').indexOf('failed') >= 0 ? 'sev-critical' : 'sev-low') + '">' + (item.action || 'action') + '</span>' +
            '<span class="alert-msg">' + (item.message || item.status || 'done') + actor + (item.delivery_id ? (' · ' + item.delivery_id) : '') + note + counts + (ticket ? (' · ' + ticket) : '') + '</span>' +
            '<span class="alert-time">' + formatTime(item.performed_at) + '</span>' +
            '</div>';
        }).join('');
      }
    }
  } catch (e) {
    document.getElementById('deliveryList').innerHTML = '<div class="error">Delivery health unavailable. ' + escapeHTML(apiErrorHint(e)) + '</div>';
    const historyList = document.getElementById('deliveryHistoryList');
    if (historyList) {
      historyList.innerHTML = '<div class="error">Delivery action history unavailable. Check delivery queue storage and server logs.</div>';
    }
  }
}

function renderDeliveryItem(item, label) {
  const ticket = item.ticket_key ? (' · ticket ' + item.ticket_key) : '';
  return '<div class="alert-item">' +
    '<span class="alert-sev ' + (item.status === 'dead_letter' ? 'sev-critical' : 'sev-medium') + '">' + escapeHTML(label || item.status || 'delivery') + '</span>' +
    '<span class="alert-msg">' + escapeHTML(item.id || '--') + ' · ' + escapeHTML(item.notifier || 'notifier') + ' · ' + escapeHTML(item.pattern || 'alert') + ' · attempt ' + (item.attempt || 1) + '/' + (item.max_attempts || 1) + escapeHTML(ticket) + (item.error ? (' · ' + escapeHTML(item.error)) : '') + '</span>' +
    '<span class="alert-time">' + formatTime(item.last_attempt_at) + '</span>' +
    '</div>';
}

function showDeliveriesByStatus(status) {
  const data = latestDeliveries || {};
  const recent = data.recent || [];
  const dead = data.dead_letters || [];
  const all = recent.concat(dead);
  const selected = status === 'recent' ? recent : all.filter(item => String(item.status || '').toLowerCase() === status);
  const items = selected.slice(0, 20).map(item => renderDeliveryItem(item, status));
  const history = data.history || [];
  if (status === 'recent') {
    history.slice(0, 5).forEach(item => items.push(renderKVItem(item.action || 'delivery action', item.message || item.status || 'done', formatTime(item.performed_at))));
  }
  setInvestigationItems(items, 'No ' + status + ' deliveries found');
}

function showDeliveryRisk(scope) {
  const data = latestDeliveries || {};
  const all = (data.recent || []).concat(data.dead_letters || []);
  let groups = [];
  if (scope === 'channels') {
    groups = countBy(all, item => item.notifier);
  } else if (scope === 'tickets') {
    groups = countBy(all.filter(item => item.ticket_key), item => item.ticket_key);
  } else {
    groups = countBy(all.filter(item => item.error), item => String(item.error || '').split(':')[0].slice(0, 40));
  }
  const items = groups.map(group => {
    return '<div class="alert-item">' +
      '<span class="alert-sev sev-medium">' + escapeHTML(scope) + '</span>' +
      '<span class="alert-msg">' + escapeHTML(group.key) + ' · ' + group.count + ' record(s)' +
      '<span class="delivery-inline-actions"><button data-delivery-key="' + escapeHTML(group.key) + '" data-delivery-scope="' + escapeHTML(scope) + '" onclick="showDeliveryGroupFromButton(this)">Drill Down</button></span></span>' +
      '<span class="alert-time">delivery</span>' +
      '</div>';
  });
  setInvestigationItems(items, 'No delivery ' + scope + ' risk found');
}

function showDeliveryGroupFromButton(button) {
  showDeliveryGroup(button.dataset.deliveryKey || '', button.dataset.deliveryScope || '');
}

function showDeliveryGroup(key, scope) {
  const data = latestDeliveries || {};
  const all = (data.recent || []).concat(data.dead_letters || []);
  const selected = all.filter(item => {
    if (scope === 'channels') return String(item.notifier || 'unknown') === key;
    if (scope === 'tickets') return String(item.ticket_key || 'unknown') === key;
    return String(item.error || '').split(':')[0].slice(0, 40) === key;
  });
  setInvestigationItems(selected.slice(0, 20).map(item => renderDeliveryItem(item, scope)), 'No delivery records found for ' + key);
}

async function runDeliveryAction(payload) {
  const status = document.getElementById('deliveryActionStatus');
  const replayAllBtn = document.getElementById('replayAllBtn');
  const createAllTicketsBtn = document.getElementById('createAllTicketsBtn');
  const refreshBtn = document.getElementById('refreshDeliveryBtn');
  if (status) {
    status.textContent = 'Running ' + payload.action + '...';
  }
  if (replayAllBtn) replayAllBtn.disabled = true;
  if (createAllTicketsBtn) createAllTicketsBtn.disabled = true;
  if (refreshBtn) refreshBtn.disabled = true;
  try {
    const data = await postJSON('/api/v1/control/deliveries', payload);
    if (status) {
      status.textContent = data.message || data.status || 'Action completed';
    }
    await loadDeliveries();
  } catch (e) {
    if (status) {
      status.textContent = 'Action failed: ' + e.message;
    }
  } finally {
    if (replayAllBtn) replayAllBtn.disabled = currentRole !== 'admin';
    if (createAllTicketsBtn) createAllTicketsBtn.disabled = currentRole !== 'admin';
    if (refreshBtn) refreshBtn.disabled = false;
  }
}

function prepareDeliveryAction(action, deliveryID) {
  const payload = {
    action: action,
    note: 'dashboard ' + action,
  };
  if (deliveryID) {
    payload.delivery_id = deliveryID;
  }
  runDeliveryAction(payload);
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
