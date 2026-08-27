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
