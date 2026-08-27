async function loadAlertWorkflow() {
  try {
    const data = await fetchJSON('/api/v1/control/alerts');
    latestWorkflow = data;
    const summary = data.summary || {};
    setText('awOpen', summary.open || 0);
    setText('awOpenDetail', summary.open || 0);
    setText('awAssigned', summary.assigned || 0);
    setText('awSuppressed', summary.suppressed || 0);
    setText('awClosed', summary.closed || 0);

    const list = document.getElementById('workflowAlertsList');
    const historyList = document.getElementById('workflowHistoryList');
    const alerts = data.alerts || [];
    const history = data.history || [];
    updateAlertQualityMetrics(alerts);
    renderAlertWorkflowList(alerts);
    if (historyList) {
      if (history.length === 0) {
        historyList.innerHTML = '<div class="loading">No workflow actions recorded yet</div>';
      } else {
        historyList.innerHTML = history.slice(0, 8).map(item => {
          const actor = item.actor ? ' · ' + item.actor : '';
          const note = item.note ? ' · note: ' + item.note : '';
          const target = item.target_id ? ' · ' + item.target_id : '';
          return '<div class="alert-item">' +
            '<span class="alert-sev ' + (String(item.status || '').indexOf('fail') >= 0 ? 'sev-critical' : 'sev-low') + '">' + (item.action || 'action') + '</span>' +
            '<span class="alert-msg">' + (item.message || item.status || 'done') + actor + target + note + '</span>' +
            '<span class="alert-time">' + formatTime(item.performed_at) + '</span>' +
            '</div>';
        }).join('');
      }
    }
  } catch (e) {
    document.getElementById('workflowAlertsList').innerHTML = renderEmptyDiagnostic('Workflow alerts unavailable.', [
      apiErrorHint(e),
      'Check /api/v1/control/alerts, alert storage retention, and control-plane logs.',
      'Generate a test event after confirming rules are enabled.',
    ]);
    const historyList = document.getElementById('workflowHistoryList');
    if (historyList) {
      historyList.innerHTML = '<div class="error">Workflow action history unavailable. Check alert workflow storage and server logs.</div>';
    }
  }
}

function collectAlertWorkflowFilters() {
  alertWorkflowFilters = {
    status: String((document.getElementById('workflowFilterStatus') || {}).value || '').toLowerCase(),
    severity: String((document.getElementById('workflowFilterSeverity') || {}).value || '').toLowerCase(),
    host: String((document.getElementById('workflowFilterHost') || {}).value || '').toLowerCase().trim(),
    rule: String((document.getElementById('workflowFilterRule') || {}).value || '').toLowerCase().trim(),
    time: String((document.getElementById('workflowFilterTime') || {}).value || '').toLowerCase().trim(),
  };
  return alertWorkflowFilters;
}

function alertMatchesWorkflowFilters(alert, filters) {
  const f = filters || alertWorkflowFilters || {};
  const status = String(alert.status || 'open').toLowerCase();
  const severity = String(alert.severity || 'info').toLowerCase();
  const hostText = [alert.hostname, alert.host, alert.agent_id, alert.node, alert.source].join(' ').toLowerCase();
  const ruleText = [alert.id, alert.rule_id, alert.pattern, alert.headline, alert.reason, alert.assignee].join(' ').toLowerCase();
  const timeText = [alert.first_seen, alert.last_seen, alert.last_notified_at, alert.sla_deadline].map(formatTime).join(' ').toLowerCase();
  if (f.status && status !== f.status) return false;
  if (f.severity && severity !== f.severity) return false;
  if (f.host && hostText.indexOf(f.host) < 0) return false;
  if (f.rule && ruleText.indexOf(f.rule) < 0) return false;
  if (f.time && timeText.indexOf(f.time) < 0) return false;
  return true;
}

function filteredAlertWorkflowAlerts() {
  const filters = collectAlertWorkflowFilters();
  return (latestWorkflow.alerts || []).filter(alert => alertMatchesWorkflowFilters(alert, filters));
}

function renderAlertWorkflowList(alerts) {
  const list = document.getElementById('workflowAlertsList');
  const summary = document.getElementById('workflowFilterSummary');
  if (!list) return;
  const all = alerts || latestWorkflow.alerts || [];
  const filters = collectAlertWorkflowFilters();
  const filtered = all.filter(alert => alertMatchesWorkflowFilters(alert, filters));
  const keyed = filtered.map((alert, index) => ({ alert: alert, key: workflowAlertKey(alert, index) }));
  if (keyed.length > 0 && !keyed.some(item => item.key === selectedWorkflowAlertKey)) {
    selectedWorkflowAlertKey = keyed[0].key;
  }
  if (summary) {
    const active = Object.keys(filters).filter(key => filters[key]).map(key => key + '=' + filters[key]);
    const selectedIndex = keyed.findIndex(item => item.key === selectedWorkflowAlertKey);
    summary.textContent = 'Showing ' + filtered.length + ' of ' + all.length + ' alerts' + (active.length ? ' · filters: ' + active.join(', ') : ' · no filters') + (selectedIndex >= 0 ? ' · selected #' + (selectedIndex + 1) : '');
  }
  if (filtered.length === 0) {
    list.innerHTML = renderEmptyDiagnostic('No workflow alerts. Generate a test event, review active rules, or lower the alert filter severity.', [
      'Reset filters or broaden severity/status/time criteria.',
      'Confirm active rules are deployed and agents are reporting.',
      'Use Recent Events to verify raw telemetry before expecting alerts.',
    ]);
    selectedWorkflowAlertKey = '';
    return;
  }
  list.innerHTML = filtered.slice(0, 25).map((alert, index) => renderWorkflowAlert(alert, workflowAlertKey(alert, index))).join('');
  scheduleDashboardMasonry();
}

function applyAlertWorkflowFilters() {
  renderAlertWorkflowList(latestWorkflow.alerts || []);
}

function resetAlertWorkflowFilters() {
  ['workflowFilterStatus', 'workflowFilterSeverity', 'workflowFilterHost', 'workflowFilterRule', 'workflowFilterTime'].forEach(id => {
    const element = document.getElementById(id);
    if (element) element.value = '';
  });
  applyAlertWorkflowFilters();
}

function normalizeAlertClassification(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (normalized === 'tp') return 'true_positive';
  if (normalized === 'fp') return 'false_positive';
  if (normalized === 'true_positive' || normalized === 'false_positive' || normalized === 'benign' || normalized === 'duplicate') {
    return normalized;
  }
  return 'needs_review';
}

function alertClassification(alert) {
  const details = alert.details || {};
  return normalizeAlertClassification(details.classification || alert.classification || alert.analyst_label);
}

function computeAlertQuality(alerts) {
  const records = alerts || [];
  const metrics = {
    schema: 'providapt.alert_quality.dashboard.v1',
    generated_at: new Date().toISOString(),
    total_alerts: records.length,
    reviewed_alerts: 0,
    unreviewed_alerts: 0,
    true_positive: 0,
    false_positive: 0,
    benign: 0,
    duplicate: 0,
    by_pattern: {},
    by_classification: {},
    recommendations: [],
  };
  records.forEach(alert => {
    const classification = alertClassification(alert);
    metrics.by_classification[classification] = (metrics.by_classification[classification] || 0) + 1;
    const pattern = String(alert.pattern || alert.headline || 'unknown');
    metrics.by_pattern[pattern] = metrics.by_pattern[pattern] || { total: 0, true_positive: 0, false_positive: 0, benign: 0, duplicate: 0, needs_review: 0 };
    metrics.by_pattern[pattern].total += 1;
    metrics.by_pattern[pattern][classification] = (metrics.by_pattern[pattern][classification] || 0) + 1;
    if (classification === 'needs_review') {
      metrics.unreviewed_alerts += 1;
    } else {
      metrics.reviewed_alerts += 1;
    }
    if (classification === 'true_positive') metrics.true_positive += 1;
    if (classification === 'false_positive') metrics.false_positive += 1;
    if (classification === 'benign') metrics.benign += 1;
    if (classification === 'duplicate') metrics.duplicate += 1;
  });
  const actionable = metrics.true_positive + metrics.false_positive + metrics.benign;
  metrics.review_coverage_percent = metrics.total_alerts ? Number((metrics.reviewed_alerts * 100 / metrics.total_alerts).toFixed(1)) : 0;
  metrics.actionable_precision_percent = actionable ? Number((metrics.true_positive * 100 / actionable).toFixed(1)) : 0;
  metrics.duplicate_percent = metrics.total_alerts ? Number((metrics.duplicate * 100 / metrics.total_alerts).toFixed(1)) : 0;
  if (metrics.unreviewed_alerts > 0) metrics.recommendations.push('Review unclassified alerts before using the dataset for detector training.');
  if (metrics.duplicate_percent >= 15) metrics.recommendations.push('Tune suppression or grouping because duplicate alerts are high.');
  if (metrics.reviewed_alerts > 0 && metrics.actionable_precision_percent < 70) metrics.recommendations.push('Prioritize noisy rules with low analyst-confirmed precision.');
  if (metrics.recommendations.length === 0) metrics.recommendations.push('Alert quality is ready for release evidence review.');
  return metrics;
}

function updateAlertQualityMetrics(alerts) {
  const metrics = computeAlertQuality(alerts);
  setText('awReviewed', metrics.review_coverage_percent + '%');
  setText('awPrecision', metrics.actionable_precision_percent + '%');
  setText('awDuplicates', metrics.duplicate);
  setText('awNeedsReview', metrics.unreviewed_alerts);
  return metrics;
}

function showAlertQuality() {
  const alerts = latestWorkflow.alerts || [];
  const metrics = updateAlertQualityMetrics(alerts);
  const noisyPatterns = Object.keys(metrics.by_pattern).sort((a, b) => {
    const left = metrics.by_pattern[a];
    const right = metrics.by_pattern[b];
    return (right.false_positive + right.benign + right.duplicate) - (left.false_positive + left.benign + left.duplicate);
  }).slice(0, 5);
  const items = [
    renderKVItem('review coverage', metrics.review_coverage_percent + '%', metrics.reviewed_alerts + ' reviewed · ' + metrics.unreviewed_alerts + ' needs review'),
    renderKVItem('precision', metrics.actionable_precision_percent + '%', metrics.true_positive + ' TP · ' + metrics.false_positive + ' FP · ' + metrics.benign + ' benign'),
    renderKVItem('duplicates', metrics.duplicate_percent + '%', metrics.duplicate + ' duplicate alerts'),
  ];
  noisyPatterns.forEach(pattern => {
    const row = metrics.by_pattern[pattern];
    items.push(renderKVItem('pattern quality', pattern, row.total + ' total · ' + row.true_positive + ' TP · ' + (row.false_positive + row.benign + row.duplicate) + ' noisy'));
  });
  metrics.recommendations.forEach(message => items.push(renderKVItem('recommendation', message, 'alert quality')));
  setInvestigationItems(items, 'No alert quality metrics available');
}

function filterAlertQuality(classification) {
  const normalized = normalizeAlertClassification(classification);
  const alerts = (latestWorkflow.alerts || []).filter(alert => alertClassification(alert) === normalized);
  document.getElementById('workflowAlertsList').innerHTML = alerts.length === 0
    ? '<div class="loading">No ' + escapeHTML(normalized) + ' workflow alerts</div>'
    : alerts.slice(0, 12).map(a => renderWorkflowAlert(a)).join('');
  setInvestigationItems(alerts.slice(0, 20).map(a => renderWorkflowAlert(a)), 'No ' + normalized + ' workflow alerts');
}

function downloadAlertQuality() {
  const metrics = updateAlertQualityMetrics(latestWorkflow.alerts || []);
  downloadTextFile('providapt-alert-quality-dashboard.json', JSON.stringify(metrics, null, 2) + '\n');
  setInvestigationItems([
    renderKVItem('alert quality export', metrics.total_alerts + ' alerts', metrics.review_coverage_percent + '% reviewed'),
    renderKVItem('precision', metrics.actionable_precision_percent + '%', metrics.true_positive + ' true positive alerts'),
  ], 'Alert quality export prepared');
}

function openAlertFeedbackLedger() {
  openProtectedEndpoint('/api/v1/control/alerts/feedback?format=csv', 'providapt-alert-feedback.csv');
  setInvestigationItems([
    renderKVItem('feedback ledger', 'CSV export requested', '/api/v1/control/alerts/feedback?format=csv'),
    renderKVItem('audit use', 'analyst labels, workflow actions, actor, role, timestamp', 'append-only evidence')
  ], 'Alert feedback ledger export opened');
}

function workflowActionButtons(alert) {
  if (currentRole !== 'admin') {
    return '<span class="delivery-inline-actions"><button class="btn-disabled-context" disabled title="Alert workflow actions require admin role">Admin only</button></span>';
  }
  const id = jsString(alert.id || '');
  const status = String(alert.status || '').toLowerCase();
  const assign = "<button data-module=\"alert-workflow\" data-module-action=\"assign\" onclick=\"event.stopPropagation(); runAlertWorkflowAction('assign', 'REPLACE_ID')\">Assign</button>";
  const silence = "<button data-module=\"alert-workflow\" data-module-action=\"silence\" class=\"secondary\" onclick=\"event.stopPropagation(); runAlertWorkflowAction('silence', 'REPLACE_ID')\">Silence 30m</button>";
  const unsilence = "<button data-module=\"alert-workflow\" data-module-action=\"unsilence\" class=\"secondary\" onclick=\"event.stopPropagation(); runAlertWorkflowAction('unsilence', 'REPLACE_ID')\">Unsilence</button>";
  const close = "<button data-module=\"alert-workflow\" data-module-action=\"close\" class=\"secondary\" onclick=\"event.stopPropagation(); runAlertWorkflowAction('close', 'REPLACE_ID')\">Close</button>";
  const reopen = "<button data-module=\"alert-workflow\" data-module-action=\"reopen\" onclick=\"event.stopPropagation(); runAlertWorkflowAction('reopen', 'REPLACE_ID')\">Reopen</button>";
  const tp = "<button data-module=\"alert-workflow\" data-module-action=\"annotate_tp\" class=\"secondary\" onclick=\"event.stopPropagation(); runAlertWorkflowAction('annotate_tp', 'REPLACE_ID')\">TP</button>";
  const fp = "<button data-module=\"alert-workflow\" data-module-action=\"annotate_fp\" class=\"secondary\" onclick=\"event.stopPropagation(); runAlertWorkflowAction('annotate_fp', 'REPLACE_ID')\">FP</button>";
  const actions = [];
  if (status !== 'assigned') actions.push(assign);
  if (status === 'suppressed') actions.push(unsilence); else actions.push(silence);
  if (status === 'closed') actions.push(reopen); else actions.push(close);
  actions.push(tp, fp);
  return '<span class="delivery-inline-actions">' + actions.join('').replace(/REPLACE_ID/g, id) + '</span>';
}

function workflowAlertKey(alert, index) {
  return [
    index,
    alert.id || '',
    alert.last_seen || alert.last_notified_at || alert.created_at || '',
    alert.headline || alert.pattern || '',
    alert.source || alert.hostname || alert.agent_id || '',
  ].join('|');
}

function workflowSelectButton(alertKey) {
  const key = jsString(alertKey || '');
  return '<button class="secondary" onclick="event.stopPropagation(); selectWorkflowAlert(\'' + key + '\')">' + (selectedWorkflowAlertKey === alertKey ? 'Selected' : 'Select') + '</button>';
}

function renderWorkflowAlertDetail(alert) {
  const meta = [
    formatSeverity(alert.severity || 'info'),
    'status ' + (alert.status || 'open'),
    'count x' + (alert.count || 1),
    alert.assignee ? ('assignee ' + alert.assignee) : 'unassigned',
    alert.source || alert.hostname || alert.agent_id || '',
  ].filter(Boolean).map(escapeHTML).join(' · ');
  return '<div class="workflow-alert-detail">' +
    '<div class="workflow-selection-head">' +
      '<span class="alert-sev ' + getSeverityClass(alert.severity || 'info') + '">' + formatSeverity(alert.severity || 'info') + '</span>' +
      '<div class="workflow-selection-title">' + escapeHTML(alert.headline || alert.pattern || alert.id || 'Alert') + '</div>' +
      '<div class="workflow-selection-meta">' + meta + '</div>' +
      '<div class="workflow-selection-meta">' + escapeHTML(formatTime(alert.first_seen || alert.created_at)) + ' → ' + escapeHTML(formatTime(alert.last_seen || alert.last_notified_at || alert.sla_deadline)) + '</div>' +
    '</div>' +
    '<div class="workflow-selection-reason">' + escapeHTML(alert.reason || alert.pattern || 'No reason supplied.') + '</div>' +
    '<div class="workflow-alert-actions primary-actions">' + workflowActionButtons(alert) + alertTraceActions(alert) + '</div>' +
    '</div>';
}

function selectWorkflowAlert(alertKey) {
  selectedWorkflowAlertKey = alertKey || '';
  renderAlertWorkflowList(latestWorkflow.alerts || []);
}

function renderWorkflowAlert(a, alertKey) {
  const sev = a.severity || 'info';
  const sla = a.sla_status ? (' · SLA ' + escapeHTML(a.sla_status)) : '';
  const encoded = inlineJSONPayload(a || {});
  const headline = escapeHTML(truncateText(a.headline || a.pattern || 'Alert', 150));
  const meta = [
    'status ' + escapeHTML(a.status || 'open'),
    a.assignee ? ('assignee ' + escapeHTML(a.assignee)) : '',
    'count x' + escapeHTML(a.count || 1),
    sla ? sla.replace(/^ · /, '') : '',
    a.hostname || a.agent_id || a.source ? ('source ' + escapeHTML(a.hostname || a.agent_id || a.source)) : '',
  ].filter(Boolean).join(' · ');
  const key = alertKey || workflowAlertKey(a, 0);
  const selected = selectedWorkflowAlertKey === key ? ' selected' : '';
  const keyLiteral = jsString(key);
  return '<div class="alert-item workflow-alert-card clickable' + selected + '" tabindex="0" role="button" onclick="if(event.target.closest(\'button,a\')) return; selectWorkflowAlert(\'' + keyLiteral + '\')" onkeydown="handleCardKey(event, function(){ selectWorkflowAlert(\'' + keyLiteral + '\'); })">' +
    '<span class="alert-sev ' + getSeverityClass(sev) + '">' + formatSeverity(sev) + '</span>' +
    '<span class="workflow-alert-main">' +
      '<span class="workflow-alert-title">' + headline + '</span>' +
      '<span class="workflow-alert-meta">' + escapeHTML(truncateText(meta, 170)) + '</span>' +
    '</span>' +
    '<span class="alert-time">' + formatTime(a.sla_deadline || a.last_seen || a.last_notified_at) + '</span>' +
    '<span class="workflow-alert-actions">' + workflowSelectButton(key) + '<button class="secondary" onclick="event.stopPropagation(); showAlertDetailsEncoded(\'' + encoded + '\')">Details</button></span>' +
    renderWorkflowAlertDetail(a) +
    '</div>';
}

async function loadAlertWorkflowFiltered(status) {
  try {
    const data = await fetchJSON('/api/v1/control/alerts?status=' + encodeURIComponent(status));
    latestWorkflow = data;
    const alerts = data.alerts || [];
    const statusInput = document.getElementById('workflowFilterStatus');
    if (statusInput) statusInput.value = status;
    renderAlertWorkflowList(alerts);
    setInvestigationItems(alerts.slice(0, 20).map(a => renderWorkflowAlert(a)), 'No ' + status + ' workflow alerts');
  } catch (e) {
    setInvestigationLoading('Workflow filter failed: ' + e.message);
  }
}

async function runAlertWorkflowAction(action, alertID) {
  if (!requireAdminAction('Alert workflow action') || !alertID) {
    return;
  }
  const payload = {
    action: action,
    alert_id: alertID,
    note: 'dashboard ' + action,
  };
  if (action === 'annotate_tp' || action === 'annotate_fp') {
    payload.action = 'annotate';
    payload.classification = action === 'annotate_tp' ? 'true_positive' : 'false_positive';
    payload.note = 'dashboard analyst feedback: ' + payload.classification;
  }
  if (action === 'assign') {
    payload.assignee = currentRole + '-operator';
  }
  if (action === 'silence') {
    payload.duration = '30m';
  }
  try {
    setModuleStatus('alert-workflow', 'Running alert workflow action: ' + action + '...');
    await postJSON('/api/v1/control/alerts', payload);
    await loadAlertWorkflow();
    const updated = (latestWorkflow.alerts || []).find(item => item.id === alertID);
    setModuleStatus('alert-workflow', 'Alert workflow action completed: ' + action);
    setInvestigationItems(updated ? [renderWorkflowAlert(updated)] : [], 'Alert action completed');
  } catch (e) {
    setModuleStatus('alert-workflow', 'Alert workflow action failed: ' + e.message);
  }
}

async function runAlertWorkflowBulkAction(action) {
  if (!requireAdminAction('Bulk alert workflow action')) {
    return;
  }
  const alerts = filteredAlertWorkflowAlerts().filter(item => String(item.status || '').toLowerCase() !== 'closed');
  const ids = alerts.slice(0, 20).map(item => item.id).filter(Boolean);
  if (ids.length === 0) {
    setModuleStatus('alert-workflow', 'No filtered active alerts available for bulk action');
    return;
  }
  setInvestigationItems([
    renderKVItem('bulk precheck', ids.length + ' filtered active alerts selected, capped at 20 per operation', action),
    renderKVItem('scope', ids.join(', '), 'selected alert ids'),
  ], 'Bulk alert precheck unavailable');
  const payload = {
    action: action,
    alert_ids: ids,
    note: 'dashboard bulk ' + action,
  };
  if (action === 'silence') {
    payload.duration = '30m';
  }
  try {
    setModuleStatus('alert-workflow', 'Running bulk alert action: ' + action + ' for ' + ids.length + ' alerts...');
    const result = await postJSON('/api/v1/control/alerts', payload);
    await loadAlertWorkflow();
    setModuleStatus('alert-workflow', 'Bulk ' + action + ': ' + (result.succeeded || 0) + ' succeeded · ' + (result.failed || 0) + ' failed');
    setInvestigationItems([
      renderKVItem('bulk ' + action, (result.succeeded || 0) + ' succeeded · ' + (result.failed || 0) + ' failed', result.status || 'done')
    ], 'Bulk alert action completed');
  } catch (e) {
    setModuleStatus('alert-workflow', 'Bulk alert workflow action failed: ' + e.message);
  }
}
