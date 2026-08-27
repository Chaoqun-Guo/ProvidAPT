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
