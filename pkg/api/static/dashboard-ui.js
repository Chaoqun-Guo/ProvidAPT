// Dashboard interaction feedback, drawer, formatting, and shared render helpers.
function migrateDashboardLayoutStorage() {
  const current = localStorage.getItem('providaptDashboardLayoutVersion');
  if (current === DASHBOARD_LAYOUT_VERSION) return;
  [
    'providaptDashboardPanelOrder',
    'providaptDashboardPanelSizes',
    'providaptDashboardViewProfile',
  ].forEach(key => localStorage.removeItem(key));
  localStorage.setItem('providaptDashboardSection', 'all');
  localStorage.setItem('providaptDashboardDensity', 'standard');
  localStorage.setItem('providaptDashboardLayoutVersion', DASHBOARD_LAYOUT_VERSION);
}

function interactionFeedback(message) {
  const info = document.getElementById('actionStatus');
  if (info) {
    info.textContent = message || 'Action received';
    info.classList.add('active');
    window.clearTimeout(interactionFeedback.timer);
    interactionFeedback.timer = window.setTimeout(() => info.classList.remove('active'), 1600);
  }
}

function requireAdminAction(actionName) {
  if (currentRole === 'admin') {
    return true;
  }
  const message = (actionName || 'Action') + ' requires admin role';
  setInvestigationLoading(message);
  updateAPIStatus(message);
  return false;
}

function installInteractionFeedback() {
  document.addEventListener('click', event => {
    const target = event.target.closest('button, .clickable');
    if (!target) return;
    target.classList.add('action-clicked');
    if (target.closest('.header-right') || target.hasAttribute('data-ui-close')) {
      window.setTimeout(() => target.classList.remove('action-clicked'), 450);
      return;
    }
    const moduleName = target.getAttribute('data-module') || '';
    const moduleAction = target.getAttribute('data-module-action') || '';
    const rawLabel = moduleName && moduleAction
      ? moduleName + ': ' + moduleAction
      : (target.textContent || target.getAttribute('aria-label') || target.title || 'Action');
    const label = rawLabel.trim().replace(/\s+/g, ' ').slice(0, 80);
    interactionFeedback(label);
    window.setTimeout(() => target.classList.remove('action-clicked'), 450);
  }, true);
  classifyDashboardButtons();
  new MutationObserver(classifyDashboardButtons).observe(document.body, { childList: true, subtree: true });
}

function classifyDashboardButtons() {
  document.querySelectorAll('button').forEach(button => {
    const text = (button.textContent || '').trim().toLowerCase();
    const action = (button.getAttribute('onclick') || '').toLowerCase();
    button.classList.remove('btn-view', 'btn-primary', 'btn-download', 'btn-warning', 'btn-danger', 'btn-refresh', 'btn-disabled-context');
    if (button.hasAttribute('data-ui-close')) {
      button.classList.add('btn-refresh');
      if (!button.title) button.title = 'Close this panel';
      return;
    }
    const haystack = text + ' ' + action;
    let kind = 'view';
    if (/(revoke|quarantine|reject|rollback|close|purge|delete|cutover)/.test(haystack)) {
      kind = 'danger';
    } else if (/(silence|apply|restore|unsilence)/.test(haystack)) {
      kind = 'warning';
    } else if (/(download|export|copy|csv|bundle|markdown|graph json)/.test(haystack)) {
      kind = 'download';
    } else if (/(refresh|retry|test|check|validate|preflight|browse|view|details|matrix|search|preview)/.test(haystack)) {
      kind = 'refresh';
    } else if (/(create|publish|approve|assign|run|generate|replay|use key|record|save)/.test(haystack)) {
      kind = 'primary';
    }
    button.classList.add('btn-' + kind);
    button.dataset.actionKind = kind;
    if (button.disabled) {
      button.classList.add('btn-disabled-context');
    }
    if (!button.title) {
      button.title = semanticButtonTitle(kind);
    }
  });
}

function semanticButtonTitle(kind) {
  switch (kind) {
  case 'danger': return 'High-impact action: review scope before running';
  case 'warning': return 'State-changing action';
  case 'download': return 'Export or download evidence';
  case 'refresh': return 'Inspect, validate, or refresh data';
  case 'primary': return 'Primary workflow action';
  default: return 'Open details';
  }
}

const moduleStatusTargets = {
  'support': 'supportBundleStatus',
  'backup': 'backupStatus',
  'policy-center': 'policyActionStatus',
  'alert-workflow': 'workflowFilterSummary',
  'delivery-health': 'deliveryActionStatus',
  'compliance-siem': 'complianceActionStatus',
  'version-update': 'actionStatus',
};

function setModuleStatus(moduleName, message) {
  const id = moduleStatusTargets[moduleName];
  const target = id ? document.getElementById(id) : null;
  if (target) {
    target.textContent = message || '';
  }
}

function modulePayload(moduleName, action, extra) {
  return Object.assign({
    action: action,
    note: moduleName + ' dashboard ' + action,
  }, extra || {});
}

function showRBACPermissions() {
  const role = currentRole || 'viewer';
  const matrix = [
    ['viewer', 'Read status, health, dashboard summaries'],
    ['analyst', 'Read investigations, alerts, policies, and evidence metadata'],
    ['auditor', 'Read audit/compliance evidence without graph export'],
    ['admin', 'Run fleet, policy, workflow, delivery, backup, upgrade, and support actions'],
  ];
  const items = matrix.map(item => renderKVItem(item[0], item[1], item[0] === role ? 'current role' : 'available role'));
  setInvestigationItems(items, 'RBAC permissions unavailable');
}

function escapeHTML(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}

function setCompactVersionText(id, value) {
  const element = document.getElementById(id);
  if (!element) return;
  const full = String(value || '--');
  const commitMatch = full.match(/commit\s+([A-Za-z0-9._-]+)/);
  const versionMatch = full.match(/v\d+(?:\.\d+){1,3}(?:-[A-Za-z0-9._-]+)?/);
  const compact = full === '--'
    ? '--'
    : [versionMatch ? versionMatch[0] : full.split(/\s+/)[0], commitMatch ? commitMatch[1] : '']
        .filter(Boolean)
        .join('...');
  element.textContent = compact.length > 28 ? compact.slice(0, 25) + '...' : compact;
  element.title = full;
}

function openDetailDrawer(title, subtitle, bodyHTML) {
  window.clearTimeout(detailDrawerHideTimer);
  setText('detailDrawerTitle', title || 'Details');
  setText('detailDrawerSubtitle', subtitle || 'Evidence details');
  const body = document.getElementById('detailDrawerBody');
  const drawer = document.getElementById('detailDrawer');
  const backdrop = document.getElementById('detailDrawerBackdrop');
  const closeButton = document.getElementById('detailDrawerClose');
  if (body) {
    body.innerHTML = bodyHTML || '<div class="empty-diagnostic">No details available.</div>';
    body.scrollTop = 0;
  }
  if (drawer) {
    drawer.hidden = false;
    drawer.classList.add('visible');
    drawer.setAttribute('aria-hidden', 'false');
    drawer.scrollTop = 0;
  }
  if (backdrop) {
    backdrop.hidden = false;
    backdrop.classList.add('visible');
  }
  document.body.classList.add('detail-drawer-open');
  classifyDashboardButtons();
  if (closeButton) {
    window.setTimeout(() => {
      try {
        closeButton.focus({ preventScroll: true });
      } catch (e) {
        closeButton.focus();
      }
    }, 0);
  }
}

function closeDetailDrawer(event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  const drawer = document.getElementById('detailDrawer');
  const backdrop = document.getElementById('detailDrawerBackdrop');
  if (drawer) {
    drawer.classList.remove('visible');
    drawer.setAttribute('aria-hidden', 'true');
  }
  if (backdrop) backdrop.classList.remove('visible');
  document.body.classList.remove('detail-drawer-open');
  detailDrawerHideTimer = window.setTimeout(() => {
    if (drawer && !drawer.classList.contains('visible')) {
      drawer.hidden = true;
    }
    if (backdrop && !backdrop.classList.contains('visible')) {
      backdrop.hidden = true;
    }
  }, 210);
}

document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    closeDetailDrawer(event);
  }
});

function renderJSONBlock(value) {
  return '<pre>' + escapeHTML(JSON.stringify(value || {}, null, 2)) + '</pre>';
}

function renderDataTable(columns, rows, emptyMessage) {
  const data = rows || [];
  if (data.length === 0) {
    return renderEmptyDiagnostic(emptyMessage || 'No table rows available', ['Adjust filters or refresh the source module.']);
  }
  return '<div class="data-table-wrap"><table class="data-table"><thead><tr>' +
    columns.map(column => '<th>' + escapeHTML(column.label || column.key) + '</th>').join('') +
    '</tr></thead><tbody>' +
    data.map(row => '<tr>' + columns.map(column => '<td>' + escapeHTML(typeof column.value === 'function' ? column.value(row) : row[column.key]) + '</td>').join('') + '</tr>').join('') +
    '</tbody></table></div>';
}

function renderDetailSection(title, bodyHTML) {
  return '<section class="detail-section">' +
    '<div class="detail-section-title">' + escapeHTML(title || 'Details') + '</div>' +
    (bodyHTML || renderEmptyDiagnostic('No details available', ['Refresh the module or adjust filters.'])) +
    '</section>';
}

function renderMetricCards(cards) {
  const items = cards || [];
  if (items.length === 0) {
    return renderEmptyDiagnostic('No summary metrics available', ['Refresh the module state.']);
  }
  return '<div class="matrix-grid">' + items.map(card =>
    '<div class="matrix-card">' +
    '<div class="label">' + escapeHTML(card.label || '') + '</div>' +
    '<div class="value">' + escapeHTML(card.value == null || card.value === '' ? '--' : card.value) + '</div>' +
    '<div class="sub">' + escapeHTML(card.sub || '') + '</div>' +
    '</div>'
  ).join('') + '</div>';
}

function renderKVItem(label, value, timeLabel) {
  return '<div class="alert-item">' +
    '<span class="alert-sev sev-low">' + escapeHTML(label) + '</span>' +
    '<span class="alert-msg">' + escapeHTML(value == null || value === '' ? '--' : value) + '</span>' +
    '<span class="alert-time">' + escapeHTML(timeLabel || '') + '</span>' +
    '</div>';
}

function renderMiniMetric(label, value, detail) {
  return '<div class="mini-card">' +
    '<div class="value">' + escapeHTML(value == null || value === '' ? '--' : value) + '</div>' +
    '<div class="label">' + escapeHTML(label || '') + '</div>' +
    '<div class="sub">' + escapeHTML(detail || '') + '</div>' +
    '</div>';
}

function renderEmptyDiagnostic(title, checks) {
  const rows = (checks || []).map(item => '<div>• ' + escapeHTML(item) + '</div>').join('');
  return '<div class="empty-diagnostic"><strong>' + escapeHTML(title || 'No data available') + '</strong>' + (rows ? '<div style="margin-top:6px;">' + rows + '</div>' : '') + '</div>';
}

function jsString(value) {
  return String(value == null ? '' : value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function inlineJSONPayload(value) {
  return encodeURIComponent(JSON.stringify(value || {}));
}

function truncateText(value, max) {
  const text = String(value == null ? '' : value);
  if (text.length <= max) return text;
  return text.slice(0, Math.max(0, max - 3)) + '...';
}

function formatNumber(value) {
  const num = Number(value || 0);
  if (!Number.isFinite(num)) return '0';
  return num % 1 === 0 ? String(num) : num.toFixed(1);
}

function handleCardKey(event, fn) {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    fn();
  }
}

function setInvestigationLoading(message) {
  const list = document.getElementById('investigationList');
  if (list) {
    list.innerHTML = '<div class="loading">' + escapeHTML(message) + '</div>';
  }
}

function setInvestigationItems(items, emptyMessage) {
  const list = document.getElementById('investigationList');
  if (!list) {
    return;
  }
  if (!items || items.length === 0) {
    list.innerHTML = '<div class="loading">' + escapeHTML(emptyMessage || 'No matching data') + '</div>';
    return;
  }
  list.innerHTML = items.join('');
}

function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
  return (b/1073741824).toFixed(2) + ' GB';
}

function formatUptime(s) {
  if (!s) return '--';
  const d = Math.floor(s/86400);
  const h = Math.floor((s%86400)/3600);
  const m = Math.floor((s%3600)/60);
  const parts = [];
  if (d > 0) parts.push(d + 'd');
  if (h > 0) parts.push(h + 'h');
  parts.push(m + 'm');
  return parts.join(' ');
}

function formatAgeSeconds(s) {
  if (s == null || s < 0) return '--';
  if (s < 60) return Math.floor(s) + 's';
  return formatUptime(s);
}

function formatTime(ts) {
  if (!ts) return '--';
  const d = new Date(ts);
  return d.toLocaleTimeString();
}

function getSeverityClass(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'sev-critical';
  if (s === 'HIGH') return 'sev-high';
  if (s === 'MEDIUM') return 'sev-medium';
  return 'sev-low';
}

function formatSeverity(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL' || s === 'HIGH' || s === 'MEDIUM') return s;
  return 'INFO';
}

function alertTraceActions(a) {
  const id = a.id || '';
  if (!id) {
    return '';
  }
  const encodedID = encodeURIComponent(id);
  const eventPattern = encodeURIComponent(a.headline || a.pattern || id);
  const alertEncoded = inlineJSONPayload(a || {});
  return '<span class="trace-actions workflow-trace-actions">' +
    '<button class="secondary" onclick="showAlertDetailsEncoded(\'' + alertEncoded + '\')">Details</button>' +
    '<button class="secondary" onclick="openTraceViewer(\'' + jsString(id) + '\')" title="Open interactive trace viewer">Open Trace</button>' +
    '<a href="/api/v1/graph/node/' + encodedID + '/backward?depth=8" target="_blank" rel="noreferrer" title="Trace upstream provenance">Backward</a>' +
    '<a href="/api/v1/graph/node/' + encodedID + '/forward?depth=8" target="_blank" rel="noreferrer" title="Trace downstream impact">Forward</a>' +
    '<a href="/api/v1/events/search?pattern=' + eventPattern + '&limit=50" target="_blank" rel="noreferrer" title="Search related raw events">Events</a>' +
    '<button class="secondary" onclick="showAlertEvents(\'' + jsString(a.headline || a.pattern || id) + '\')">Open Events</button>' +
    '</span>';
}

function updateStatus(status) {
  const badge = document.getElementById('statusBadge');
  const text = document.getElementById('statusText');
  badge.className = 'status-badge ' + (status || 'unknown');
  text.textContent = (status || 'unknown').charAt(0).toUpperCase() + (status || 'unknown').slice(1);
}

function traceViewerURL(traceID) {
  return '/api/v1/alerts/' + encodeURIComponent(traceID) + '/svg/view';
}

function openTraceViewer(traceID) {
  const id = String(traceID || '').trim();
  if (!id) return;
  window.open(traceViewerURL(id), '_blank', 'noopener,noreferrer');
}
