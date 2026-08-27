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
