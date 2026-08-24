let lastStatus = 'unknown';
let currentRole = 'admin';
let latestStatus = {};
let latestFleet = { agents: [], history: [] };
let latestOverview = { agents: [] };
let latestSupport = {};
let latestBackup = {};
let latestUpgrade = {};
let latestPolicies = {};
let latestWorkflow = { alerts: [], history: [] };
let latestDeliveries = { recent: [], dead_letters: [], history: [] };
let latestCompliance = {};
let latestGroundTruth = { records: [], phases: {}, files: [] };
let latestGroundTruthCorrelation = { records: [] };
let groundTruthFilter = 'all';
let lastAPIRequest = null;
let detailDrawerHideTimer = null;
let alertWorkflowFilters = { status: '', severity: '', host: '', rule: '', time: '' };
let selectedWorkflowAlertKey = '';
const DASHBOARD_LAYOUT_VERSION = 'stable-workbench-20260731-v6';

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

async function fetchJSON(url, options) {
  const opts = options || {};
  const suppressAuthError = opts.quietAuth || isBackgroundProtectedRead(url);
  rememberLastRequest('GET', url);
  try {
    const r = await fetch(url, { headers: authHeaders() });
    if ((r.status === 401 || r.status === 403) && !suppressAuthError) {
      updateAPIStatus('Access denied by local API policy');
    }
    if (!r.ok) throw await responseError(r, url);
    clearAPIStatus();
    return r.json();
  } catch (e) {
    if (!(suppressAuthError && isAuthzError(e))) {
      reportAPIError('GET', url, e);
    }
    throw e;
  }
}

function isAuthzError(err) {
  return !!err && (err.status === 401 || err.status === 403);
}

function isBackgroundProtectedRead(url) {
  try {
    const parsed = new URL(url, window.location.origin);
    return parsed.origin === window.location.origin && isBackgroundProtectedPath(parsed.pathname);
  } catch (e) {
    const value = String(url || '');
    return isBackgroundProtectedPath(value.split('?')[0]);
  }
}

function isBackgroundProtectedPath(pathname) {
  return pathname.indexOf('/api/v1/control/') === 0 ||
    pathname === '/api/v1/evaluation/ground-truth' ||
    pathname === '/api/v1/evaluation/correlation';
}

async function postJSON(url, payload) {
  return postJSONWithLeaderRetry(url, payload, false);
}

async function postJSONWithLeaderRetry(url, payload, retried) {
  if (!retried) {
    rememberLastRequest('POST', url, payload);
  }
  const response = await fetch(url, {
    method: 'POST',
    headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (response.status === 409 && data && data.leader_endpoint && !retried) {
    const leaderURL = leaderRequestURL(data.leader_endpoint, url);
    updateAPIStatus('Current node is follower; retrying leader ' + data.leader_endpoint);
    return postJSONWithLeaderRetry(leaderURL, payload, true);
  }
  if (!response.ok) {
    const authz = response.status === 401 || response.status === 403;
    const err = new Error(authz ? 'Access denied by local API policy' : sanitizeAPIErrorText(data.error || response.statusText));
    err.status = response.status;
    err.url = url;
    reportAPIError('POST', url, err);
    throw err;
  }
  clearAPIStatus();
  return data;
}

function leaderRequestURL(leaderEndpoint, originalURL) {
  const original = new URL(originalURL, window.location.origin);
  const leader = new URL(leaderEndpoint, window.location.origin);
  leader.pathname = original.pathname;
  leader.search = original.search;
  leader.hash = '';
  return leader.toString();
}

async function fetchJSONAnyStatus(url) {
  const r = await fetch(url, { headers: authHeaders() });
  return r.json();
}

async function responseError(response, url) {
  let message = response.statusText || 'request failed';
  try {
    const data = await response.clone().json();
    message = data.error || data.message || message;
  } catch (e) {
    try {
      const text = await response.clone().text();
      if (text) message = text.slice(0, 240);
    } catch (ignored) {
      // Keep status text.
    }
  }
  const err = new Error(message);
  err.status = response.status;
  err.url = url;
  if (response.status === 401 || response.status === 403) {
    err.message = 'Access denied by local API policy';
  } else {
    err.message = sanitizeAPIErrorText(err.message);
  }
  return err;
}

function reportAPIError(method, url, err) {
  const banner = document.getElementById('apiStatusBanner');
  const text = document.getElementById('apiStatusText');
  if (!banner || !text) {
    return;
  }
  const status = err && err.status ? ('HTTP ' + err.status) : 'network';
  const message = friendlyAPIErrorMessage(err);
  const hint = apiErrorHint(err);
  text.textContent = method + ' ' + url + ' failed (' + status + '): ' + message + '. ' + hint;
  banner.className = 'api-status-banner visible error';
}

function friendlyAPIErrorMessage(err) {
  if (err && (err.status === 401 || err.status === 403)) {
    return 'Access denied by local API policy';
  }
  const message = err && err.message ? err.message : 'request failed';
  return sanitizeAPIErrorText(message);
}

function sanitizeAPIErrorText(message) {
  const keyPhrase = 'api' + '\\s+' + 'key';
  const missingKeyPattern = new RegExp('unauthorized:\\s*missing or invalid ' + keyPhrase, 'ig');
  const keyPattern = new RegExp(keyPhrase, 'ig');
  return String(message || 'request failed')
    .replace(missingKeyPattern, 'access denied by local API policy')
    .replace(keyPattern, 'local API access');
}

function clearAPIStatus() {
  const banner = document.getElementById('apiStatusBanner');
  const text = document.getElementById('apiStatusText');
  if (!banner || !text) {
    return;
  }
  text.textContent = '';
  banner.className = 'api-status-banner';
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

function apiErrorHint(err) {
  if (err && (err.status === 401 || err.status === 403)) {
    return 'Check local API access and role permissions.';
  }
  if (err && err.status === 404) {
    return 'Confirm the endpoint is available in this build.';
  }
  if (err && err.status === 409) {
    return 'Retry against the active control-plane leader.';
  }
  return 'Check daemon health, network access, and server logs.';
}

function authHeaders() {
  return {};
}

function updateAPIStatus(message) {
  const status = document.getElementById('actionStatus');
  if (status && message) status.textContent = message;
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

function rememberLastRequest(method, url, payload) {
  lastAPIRequest = {
    method: method,
    url: url,
    payload: payload || null,
  };
}

async function retryLastRequest() {
  if (!lastAPIRequest) {
    updateAPIStatus('No API request has been recorded yet');
    return;
  }
  try {
    if (lastAPIRequest.method === 'POST') {
      await postJSON(lastAPIRequest.url, lastAPIRequest.payload || {});
    } else if (lastAPIRequest.method === 'DOWNLOAD') {
      await downloadWithAuth(lastAPIRequest.url, (lastAPIRequest.payload && lastAPIRequest.payload.file_name) || 'providapt-download');
    } else {
      await fetchJSON(lastAPIRequest.url);
    }
    updateAPIStatus('Retried ' + lastAPIRequest.method + ' ' + lastAPIRequest.url);
  } catch (e) {
    updateAPIStatus('Retry failed: ' + friendlyAPIErrorMessage(e));
  }
}

async function copyStatusCurl() {
  const command = "curl '" + window.location.origin + "/api/v1/status'";
  try {
    await navigator.clipboard.writeText(command);
    updateAPIStatus('Copied status curl command');
  } catch (e) {
    updateAPIStatus(command);
  }
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

async function openProtectedEndpoint(url, defaultName) {
  rememberLastRequest('DOWNLOAD', url, { file_name: defaultName || 'providapt-response' });
  try {
    const response = await fetch(url, { headers: authHeaders() });
    if (!response.ok) {
      const err = await responseError(response, url);
      reportAPIError('GET', url, err);
      updateAPIStatus(err.status === 401 || err.status === 403 ? 'Access denied for ' + url : 'Open failed: ' + err.message);
      return;
    }
    clearAPIStatus();
    const contentType = response.headers.get('Content-Type') || 'application/octet-stream';
    const blob = await response.blob();
    const href = URL.createObjectURL(blob);
    const opened = window.open(href, '_blank', 'noopener,noreferrer');
    if (!opened) {
      const link = document.createElement('a');
      link.href = href;
      link.download = defaultName || protectedEndpointFileName(url, contentType);
      document.body.appendChild(link);
      link.click();
      link.remove();
    }
    window.setTimeout(() => URL.revokeObjectURL(href), 30000);
  } catch (e) {
    reportAPIError('GET', url, e);
  }
}

function protectedEndpointFileName(url, contentType) {
  const safe = String(url || 'providapt-response').replace(/[^A-Za-z0-9_.-]+/g, '_').replace(/^_+|_+$/g, '');
  if (contentType.indexOf('svg') >= 0) return safe + '.svg';
  if (contentType.indexOf('html') >= 0) return safe + '.html';
  if (contentType.indexOf('json') >= 0) return safe + '.json';
  if (contentType.indexOf('csv') >= 0) return safe + '.csv';
  return safe || 'providapt-response';
}

async function downloadWithAuth(url, defaultName) {
  rememberLastRequest('DOWNLOAD', url, { file_name: defaultName });
  const response = await fetch(url, { headers: authHeaders() });
  if (!response.ok) {
    const err = await responseError(response, url);
    reportAPIError('GET', url, err);
    throw err;
  }
  clearAPIStatus();
  const blob = await response.blob();
  const disposition = response.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const fileName = match ? match[1] : defaultName;
  const href = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = href;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(href);
}

function installProtectedAPILinkHandler() {
  document.addEventListener('click', event => {
    const link = event.target.closest('a[href^="/api/v1/"]');
    if (!link || event.defaultPrevented) return;
    event.preventDefault();
    openProtectedEndpoint(link.getAttribute('href'), protectedEndpointFileName(link.getAttribute('href'), ''));
  });
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
    '<a href="/api/v1/alerts/' + encodedID + '/svg/view" target="_blank" rel="noreferrer" title="Open interactive trace viewer">Trace SVG</a>' +
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

async function loadStatus() {
  try {
    const data = await fetchJSON('/api/v1/status');
    latestStatus = data || {};
    currentRole = (data.role || 'admin').toLowerCase();
    document.getElementById('roleInfo').textContent = 'Role: ' + currentRole;
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
    boolState(diag.api_auth_enabled, 'auth', 'open'),
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
    renderKVItem('rest api', diag.api_rest || '--', boolState(diag.api_auth_enabled, 'auth enabled', 'auth disabled')),
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
    rows.push(renderKVItem('rest api', diag.api_rest || '--', boolState(diag.api_auth_enabled, 'auth enabled', 'auth disabled')));
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

async function loadControlOverview() {
  try {
    const group = document.getElementById('fleetGroup').value.trim();
    const tag = document.getElementById('fleetTag').value.trim();
    const params = new URLSearchParams();
    if (group) params.set('group', group);
    if (tag) params.set('tag', tag);
    const fleet = await fetchJSON('/api/v1/control/fleet' + (params.toString() ? '?' + params.toString() : ''));
    const data = await fetchJSON('/api/v1/control/overview');
    latestFleet = fleet;
    latestOverview = data;
    setText('mAgents', data.total_agents || 0);
    setText('mDegradedAgents', data.degraded_agents || 0);

    const list = document.getElementById('agentsList');
    const historyList = document.getElementById('fleetHistoryList');
    const agents = fleet.agents || [];
    updateFleetAggregateMetrics(agents);
    const history = fleet.history || [];
    if (agents.length === 0) {
      list.innerHTML = '<div class="loading">No agents reporting yet. Start an agent, confirm telemetry endpoint and API credentials, then refresh this panel.</div>';
    } else {
      list.innerHTML = agents.map(a => {
        const status = (a.status || 'unknown').toLowerCase();
        const reportAge = a.last_report_age_seconds != null ? formatAgeSeconds(a.last_report_age_seconds) : '--';
        const reason = a.status_reason ? (' · ' + a.status_reason) : '';
        const agentIDRaw = a.agent_id || 'unknown';
        const agentID = escapeHTML(agentIDRaw);
        const agentArg = jsString(agentIDRaw);
        const osLabel = [a.os_version || a.os || '--', a.architecture || '--'].filter(Boolean).join(' · ');
        const cpuLabel = a.cpu_count ? (a.cpu_count + ' CPU') : '--';
        const hostLabel = a.hostname || agentIDRaw || '--';
        const enrollment = a.enrollment_status || 'pending';
        const enrollmentNote = a.enrollment_note ? (' · ' + a.enrollment_note) : '';
        const certFingerprint = a.cert_fingerprint || '';
        const certLabel = certFingerprint ? (certFingerprint.length > 23 ? certFingerprint.slice(0, 23) + '…' : certFingerprint) : '--';
        const statusBadge = status && status !== 'healthy'
          ? '<span class="status-badge ' + status + '"><span class="status-dot"></span><span>' + (a.status || 'UNKNOWN') + '</span></span>'
          : '<span class="alert-time">Last report ' + reportAge + '</span>';
        return '<div class="agent-card">' +
          '<div class="agent-head">' +
            '<span class="agent-name">' + agentID + '</span>' +
            statusBadge +
          '</div>' +
          '<div class="agent-meta">' +
            '<span>Group: ' + (a.group || '--') + '</span>' +
            '<span>Version: ' + (a.version || '--') + '</span>' +
            '<span>Mode: ' + (a.attachment_mode || '--') + '</span>' +
            '<span>Events: ' + ((a.events_ingested || 0).toLocaleString()) + '</span>' +
            '<span>Dropped: ' + ((a.events_dropped || 0).toLocaleString()) + '</span>' +
            '<span>Graph: ' + ((a.graph_nodes || 0).toLocaleString()) + ' nodes / ' + ((a.graph_edges || 0).toLocaleString()) + ' edges</span>' +
            '<span>Memory: ' + formatBytes(a.memory_bytes || 0) + '</span>' +
            '<span>Policy: v' + (a.applied_policy_version || '--') + '</span>' +
            '<span>Enrollment: ' + escapeHTML(enrollment) + enrollmentNote + '</span>' +
            '<span title="' + escapeHTML(certFingerprint || 'No mTLS client certificate observed') + '">Cert: ' + escapeHTML(certLabel) + '</span>' +
            '<span>Last report: ' + formatTime(a.last_report_at) + '</span>' +
            '<span>Report age: ' + reportAge + reason + '</span>' +
          '</div>' +
          '<div class="agent-env">' +
            '<span>Environment: ' + escapeHTML(osLabel) + '</span>' +
            '<span>Hostname: ' + escapeHTML(hostLabel) + '</span>' +
            '<span>Kernel: ' + escapeHTML(a.kernel || '--') + '</span>' +
            '<span>CPU: ' + escapeHTML(cpuLabel) + '</span>' +
            '<span>Arch: ' + escapeHTML(a.architecture || '--') + '</span>' +
          '</div>' +
          (((a.tags || []).length > 0) ? ('<div class="tag-list">' + a.tags.map(t => '<span class="tag-chip">' + escapeHTML(t) + '</span>').join('') + '</div>') : '') +
          '<div class="agent-actions">' +
            '<button onclick="showAgentDetails(\'' + agentArg + '\')">Details</button>' +
            '<button onclick="applyFleetInputs(\'' + agentArg + '\')">Apply Group/Tag</button>' +
            '<button onclick="markAgentReviewed(\'' + agentArg + '\')">Mark Reviewed</button>' +
            '<button onclick="setAgentEnrollment(\'' + agentArg + '\', \'approved\')">Approve</button>' +
            '<button onclick="setAgentEnrollment(\'' + agentArg + '\', \'quarantined\')">Quarantine</button>' +
            '<button onclick="setAgentEnrollment(\'' + agentArg + '\', \'revoked\')">Revoke</button>' +
          '</div>' +
        '</div>';
      }).join('');
    }
    if (historyList) {
      if (history.length === 0) {
        historyList.innerHTML = '<div class="loading">No fleet actions recorded yet</div>';
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
    document.getElementById('agentsList').innerHTML = '<div class="error">Control plane overview unavailable. ' + escapeHTML(apiErrorHint(e)) + '</div>';
    const historyList = document.getElementById('fleetHistoryList');
    if (historyList) {
      historyList.innerHTML = '<div class="error">Fleet action history unavailable. Check control-plane state storage and server logs.</div>';
    }
  }
}

function updateFleetAggregateMetrics(agents) {
  const list = agents || [];
  if (list.length === 0) return;
  const totals = list.reduce((acc, agent) => {
    acc.events += Number(agent.events_ingested || 0);
    acc.dropped += Number(agent.events_dropped || 0);
    acc.nodes += Number(agent.graph_nodes || 0);
    acc.edges += Number(agent.graph_edges || 0);
    acc.memory += Number(agent.memory_bytes || 0);
    return acc;
  }, { events: 0, dropped: 0, nodes: 0, edges: 0, memory: 0 });
  setText('mEvents', totals.events.toLocaleString());
  setText('mDropped', totals.dropped.toLocaleString());
  if (totals.nodes > 0 || totals.edges > 0) {
    setText('mNodes', totals.nodes.toLocaleString());
    setText('mEdges', totals.edges.toLocaleString());
  }
  if (totals.memory > 0) {
    setText('mMemory', formatBytes(totals.memory));
  }
}

function renderAgentInvestigation(agent, label) {
  const status = (agent.status || 'UNKNOWN').toLowerCase();
  const tags = (agent.tags || []).join(', ') || '--';
  return '<div class="alert-item">' +
    '<span class="alert-sev ' + (status === 'healthy' ? 'sev-low' : (status === 'degraded' ? 'sev-high' : 'sev-critical')) + '">' + escapeHTML(label || status) + '</span>' +
    '<span class="alert-msg">' + escapeHTML(agent.agent_id || 'unknown') +
      ' · group ' + escapeHTML(agent.group || '--') +
      ' · tags ' + escapeHTML(tags) +
      ' · version ' + escapeHTML(agent.version || '--') +
      ' · enrollment ' + escapeHTML(agent.enrollment_status || 'pending') +
      ' · cert ' + escapeHTML(agent.cert_fingerprint ? agent.cert_fingerprint.slice(0, 23) + '…' : '--') +
      ' · events ' + ((agent.events_ingested || 0).toLocaleString()) +
      ' · graph ' + ((agent.graph_nodes || 0).toLocaleString()) + '/' + ((agent.graph_edges || 0).toLocaleString()) +
      ' · dropped ' + ((agent.events_dropped || 0).toLocaleString()) +
      (agent.status_reason ? (' · ' + escapeHTML(agent.status_reason)) : '') +
    '</span>' +
    '<span class="alert-time">' + formatTime(agent.last_report_at) + '</span>' +
    '</div>';
}

async function showFleetStatus(status) {
  setInvestigationLoading('Filtering fleet: ' + status + '...');
  try {
    const data = await fetchJSON('/api/v1/control/overview');
    latestOverview = data;
    const agents = data.agents || latestFleet.agents || [];
    const selected = status === 'all'
      ? agents
      : agents.filter(agent => String(agent.status || '').toLowerCase() === status);
    setInvestigationItems(selected.map(agent => renderAgentInvestigation(agent, status)), 'No ' + status + ' agents found');
  } catch (e) {
    setInvestigationLoading('Fleet filter unavailable: ' + e.message);
  }
}

function showAgentDetails(agentID) {
  const agents = (latestFleet.agents || []).concat(latestOverview.agents || []);
  const agent = agents.find(item => item.agent_id === agentID);
  if (!agent) {
    setInvestigationLoading('Agent not found in latest snapshot: ' + agentID);
    return;
  }
  setInvestigationItems([
    renderAgentInvestigation(agent, 'agent'),
    '<div class="alert-item"><span class="alert-sev sev-medium">runtime</span><span class="alert-msg">mode ' + escapeHTML(agent.attachment_mode || '--') + ' · memory ' + formatBytes(agent.memory_bytes || 0) + ' · report age ' + escapeHTML(formatAgeSeconds(agent.last_report_age_seconds)) + '</span><span class="alert-time">details</span></div>',
  ], 'Agent details unavailable');
  openDetailDrawer('Agent Details', agent.agent_id || agentID, [
    renderAgentInvestigation(agent, 'agent'),
    renderKVItem('environment', [agent.os_version || agent.os, agent.kernel, agent.architecture].filter(Boolean).join(' · ') || '--', (agent.cpu_count || '--') + ' CPU'),
    renderKVItem('runtime', 'mode ' + (agent.attachment_mode || '--') + ' · memory ' + formatBytes(agent.memory_bytes || 0), 'report age ' + formatAgeSeconds(agent.last_report_age_seconds)),
    renderKVItem('telemetry', (agent.events_ingested || 0) + ' events · ' + (agent.events_dropped || 0) + ' dropped', (agent.graph_nodes || 0) + '/' + (agent.graph_edges || 0) + ' graph'),
    renderJSONBlock(agent),
  ].join(''));
}

function showEnvironmentOverview() {
  const agents = (latestFleet.agents || []).concat(latestOverview.agents || []);
  const uniqueAgents = [];
  const seen = {};
  agents.forEach(agent => {
    const id = agent.agent_id || agent.hostname || JSON.stringify(agent);
    if (!seen[id]) {
      seen[id] = true;
      uniqueAgents.push(agent);
    }
  });
  const byOS = countBy(uniqueAgents, agent => agent.os_version || agent.os || 'unknown');
  const byGroup = countBy(uniqueAgents, agent => agent.group || 'default');
  const byStatus = countBy(uniqueAgents, agent => agent.status || 'unknown');
  const rows = uniqueAgents.map(agent => ({
    agent: agent.agent_id || agent.hostname || 'unknown',
    environment: [agent.os_version || agent.os, agent.kernel, agent.architecture].filter(Boolean).join(' · ') || '--',
    group: agent.group || 'default',
    tags: (agent.tags || []).join(', ') || '--',
    status: agent.status || 'unknown',
    telemetry: (agent.events_ingested || 0) + ' events / ' + (agent.events_dropped || 0) + ' dropped',
  }));
  const cards = '<div class="matrix-grid">' +
    renderEnvironmentCards('OS', byOS) +
    renderEnvironmentCards('Group', byGroup) +
    renderEnvironmentCards('Status', byStatus) +
    '</div>';
  const table = renderDataTable([
    { key: 'agent', label: 'Agent' },
    { key: 'environment', label: 'Environment' },
    { key: 'group', label: 'Group' },
    { key: 'tags', label: 'Tags' },
    { key: 'status', label: 'Status' },
    { key: 'telemetry', label: 'Telemetry' },
  ], rows, 'No agent environment records available');
  openDetailDrawer('Environment Overview', uniqueAgents.length + ' reporting agent(s)', cards + table);
}

function renderEnvironmentCards(label, groups) {
  return (groups || []).slice(0, 6).map(group => '<div class="matrix-card"><div class="label">' + escapeHTML(label) + '</div><div class="value">' + escapeHTML(group.key) + '</div><div class="sub">' + group.count + ' agent(s)</div></div>').join('');
}

async function updateFleetAgent(payload) {
  await postJSON('/api/v1/control/fleet', payload);
  await loadControlOverview();
  showAgentDetails(payload.agent_id);
}

async function applyFleetInputs(agentID) {
  if (!requireAdminAction('Fleet metadata update')) {
    return;
  }
  const group = document.getElementById('fleetGroup').value.trim();
  const tag = document.getElementById('fleetTag').value.trim();
  const payload = { agent_id: agentID, note: 'dashboard fleet update' };
  if (group) payload.group = group;
  if (tag) payload.tags = [tag];
  try {
    setInvestigationLoading('Updating fleet metadata for ' + agentID + '...');
    await updateFleetAgent(payload);
  } catch (e) {
    setInvestigationLoading('Fleet update failed: ' + e.message);
  }
}

async function markAgentReviewed(agentID) {
  if (!requireAdminAction('Mark agent reviewed')) {
    return;
  }
  try {
    setInvestigationLoading('Marking agent reviewed: ' + agentID + '...');
    await updateFleetAgent({ agent_id: agentID, note: 'dashboard reviewed' });
  } catch (e) {
    setInvestigationLoading('Agent review failed: ' + e.message);
  }
}

async function setAgentEnrollment(agentID, status) {
  if (!requireAdminAction('Fleet enrollment update')) {
    return;
  }
  try {
    setInvestigationLoading('Updating enrollment for ' + agentID + ': ' + status + '...');
    await updateFleetAgent({
      agent_id: agentID,
      action: status,
      status: status,
      note: 'dashboard enrollment ' + status,
    });
  } catch (e) {
    setInvestigationLoading('Enrollment update failed: ' + e.message);
  }
}

async function bulkFleetEnrollment(status) {
  if (!requireAdminAction('Bulk fleet enrollment')) {
    return;
  }
  const agents = latestFleet.agents || [];
  const ids = agents.map(agent => agent.agent_id).filter(Boolean);
  if (ids.length === 0) {
    setInvestigationLoading('No agents match the current group/tag filter for bulk fleet action');
    return;
  }
  try {
    setInvestigationLoading('Updating ' + ids.length + ' filtered agent(s) to ' + status + '...');
    const payload = {
      action: status,
      status: status,
      agent_ids: ids,
      note: 'dashboard bulk fleet ' + status,
    };
    await postJSON('/api/v1/control/fleet', payload);
    await loadControlOverview();
    setInvestigationItems(ids.slice(0, 20).map(id => renderKVItem('fleet', id, status)), 'Bulk fleet action completed');
  } catch (e) {
    setInvestigationLoading('Bulk fleet action failed: ' + e.message);
  }
}

async function loadPolicies() {
  try {
    const data = await fetchJSON('/api/v1/control/policies');
    latestPolicies = data;
    document.getElementById('pCurrentVersion').textContent = (data.current && data.current.version) || '--';
    document.getElementById('pDraftState').textContent = (data.draft && data.draft.state) || '--';
    document.getElementById('pActiveRules').textContent = (data.current && data.current.active_rules) || 0;
    document.getElementById('pHistoryCount').textContent = (data.history || []).length;
    document.getElementById('pDeploymentStatus').textContent = (data.current && data.current.deployment_status) || '--';
    const historyList = document.getElementById('policyHistoryList');
    const actions = data.actions || [];
    if (historyList) {
      if (actions.length === 0) {
        historyList.innerHTML = '<div class="loading">No policy actions recorded yet</div>';
      } else {
        historyList.innerHTML = actions.slice(0, 8).map(item => {
          const actor = item.actor ? ' · ' + item.actor : '';
          const note = item.note ? ' · note: ' + item.note : '';
          const target = item.target_id ? ' · ' + item.target_id : '';
          const encoded = jsString(JSON.stringify(item || {}));
          return '<div class="alert-item clickable" tabindex="0" role="button" onclick="showPolicyActionDetails(\'' + encoded + '\')">' +
            '<span class="alert-sev ' + (String(item.status || '').indexOf('fail') >= 0 ? 'sev-critical' : 'sev-low') + '">' + (item.action || 'action') + '</span>' +
            '<span class="alert-msg">' + (item.message || item.status || 'done') + actor + target + note + '</span>' +
            '<span class="alert-time">' + formatTime(item.performed_at) + '</span>' +
            '</div>';
        }).join('');
      }
    }
  } catch (e) {
    if (isAuthzError(e)) {
      latestPolicies = { restricted: true };
      setText('pCurrentVersion', 'restricted');
      setText('pDraftState', '--');
      setText('pActiveRules', '--');
      setText('pHistoryCount', '--');
      setText('pDeploymentStatus', 'restricted');
      const historyList = document.getElementById('policyHistoryList');
      if (historyList) {
        historyList.innerHTML = '<div class="loading">Policy center requires local API access with policy permissions.</div>';
      }
      setModuleStatus('policy-center', 'Policy center is restricted by local API permissions.');
      return;
    }
    document.getElementById('pCurrentVersion').textContent = 'err';
    setModuleStatus('policy-center', 'Policy center unavailable: ' + e.message);
  }
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

function showPolicyDetails(scope) {
  const data = latestPolicies || {};
  const current = data.current || {};
  const draft = data.draft || {};
  const history = data.history || [];
  const actions = data.actions || [];
  let rows = [];
  let tableColumns = [
    { key: 'name', label: 'Item' },
    { key: 'value', label: 'Value' },
    { key: 'detail', label: 'Detail' },
  ];
  if (scope === 'current') {
    rows = [
      { name: 'current', value: 'version ' + (current.version || '--') + ' · state ' + (current.state || '--') + ' · rules ' + (current.active_rules || 0), detail: formatTime(current.published_at || current.updated_at) },
      { name: 'sigma', value: (current.sigma_rule_ids || []).join(', ') || '--', detail: 'rules' },
      { name: 'bundle sha256', value: current.bundle_sha256 || '--', detail: 'integrity' },
      { name: 'bundle path', value: current.bundle_path || '--', detail: 'local' },
    ];
  } else if (scope === 'draft') {
    rows = [{ name: 'draft', value: 'version ' + (draft.version || '--') + ' · state ' + (draft.state || '--') + ' · rules ' + (draft.active_rules || 0), detail: formatTime(draft.updated_at) }];
  } else if (scope === 'rules') {
    rows = [
      { name: 'active', value: current.active_rules || 0, detail: 'rules' },
      { name: 'whitelist', value: current.whitelist_count || 0, detail: 'entries' },
      { name: 'taint sources', value: current.taint_source_count || 0, detail: 'entries' },
    ];
  } else if (scope === 'deployment') {
    rows = [
      { name: 'status', value: current.deployment_status || '--', detail: 'current' },
      { name: 'target scope', value: (current.target_group || 'all groups') + ' · ' + (current.target_tag || 'all tags'), detail: 'filter' },
      { name: 'target agents', value: current.target_agents || 0, detail: 'agents' },
      { name: 'acknowledged', value: current.acked_agents || 0, detail: 'agents' },
      { name: 'pending', value: current.pending_agents || 0, detail: 'agents' },
      { name: 'bundle', value: current.bundle_sha256 || '--', detail: 'sha256' },
      { name: 'note', value: 'queued means rollout is waiting for agent telemetry acknowledgement; applied means all targeted agents reported the policy version', detail: 'state' },
    ];
  } else if (scope === 'diff') {
    const diff = data.diff || [];
    tableColumns = [
      { key: 'field', label: 'Field' },
      { key: 'before', label: 'Before' },
      { key: 'after', label: 'After' },
      { key: 'status', label: 'Status' },
    ];
    rows = diff.map(item => ({
      field: item.field || 'policy',
      before: item.before == null || item.before === '' ? '--' : JSON.stringify(item.before),
      after: item.after == null || item.after === '' ? '--' : JSON.stringify(item.after),
      status: item.status || 'changed',
    }));
  } else {
    rows = history.slice(0, 10).map(item => ({ name: 'v' + (item.version || '--'), value: (item.state || '--') + ' · rules ' + (item.active_rules || 0) + (item.notes ? (' · ' + item.notes) : ''), detail: formatTime(item.published_at || item.updated_at) }));
    rows = rows.concat(actions.slice(0, 5).map(item => ({ name: item.action || 'action', value: (item.message || item.status || 'done') + (item.actor ? (' · ' + item.actor) : ''), detail: formatTime(item.performed_at) })));
  }
  const listItems = scope === 'diff'
    ? rows.map(row => renderKVItem(row.field, 'Before: ' + row.before + ' · After: ' + row.after, row.status))
    : rows.map(row => renderKVItem(row.name, row.value, row.detail));
  const cards = renderMetricCards([
    { label: 'Current', value: current.version || '--', sub: current.state || 'state unknown' },
    { label: 'Draft', value: draft.version || '--', sub: draft.state || 'state unknown' },
    { label: 'Rules', value: current.active_rules || 0, sub: 'active sigma rules' },
    { label: 'Actions', value: actions.length, sub: 'audit records' },
  ]);
  const body = [
    renderDetailSection('Policy Summary', cards),
    renderDetailSection('Selected View', renderDataTable(tableColumns, rows, 'No policy details available')),
    renderDetailSection('Raw Evidence', renderJSONBlock({ current: current, draft: draft, history_count: history.length, action_count: actions.length })),
  ].join('');
  setInvestigationItems(listItems, 'No policy details available');
  openDetailDrawer('Policy Center · ' + (scope || 'history'), 'Current policy, draft, rollout, rules, and audit evidence', body);
}

function showPolicyActionDetails(encoded) {
  try {
    const item = JSON.parse(encoded || '{}');
    const rows = [
      renderKVItem('action', item.action || '--', item.status || '--'),
      renderKVItem('actor', item.actor || '--', item.role || 'role'),
      renderKVItem('target', item.target_id || item.target || '--', item.source || 'policy'),
      renderKVItem('performed', formatTime(item.performed_at || item.timestamp), item.message || item.note || ''),
      renderJSONBlock(item),
    ];
    openDetailDrawer('Policy Audit Action', item.action || 'policy action', rows.join(''));
  } catch (e) {
    setInvestigationLoading('Policy action detail parse failed: ' + e.message);
  }
}

function renderPolicyDiffItem(item) {
  const before = item.before == null || item.before === '' ? '--' : JSON.stringify(item.before);
  const after = item.after == null || item.after === '' ? '--' : JSON.stringify(item.after);
  return renderKVItem(
    item.field || 'policy',
    'Before: ' + before + ' · After: ' + after,
    item.status || 'changed'
  );
}

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
    ? '<a href="/api/v1/alerts/' + encodeURIComponent(nodeID) + '/svg/view" target="_blank" rel="noreferrer">Trace SVG</a>'
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

async function runPolicyAction(payload) {
  const status = document.getElementById('policyActionStatus');
  if (status) {
    status.textContent = 'Running ' + payload.action + '...';
  }
  try {
    const result = await postJSON('/api/v1/control/policies', payload);
    if (status) {
      status.textContent = policySuccessMessage(payload.action, result);
    }
    await loadPolicies();
  } catch (e) {
    if (status) {
      status.textContent = 'Policy action failed: ' + e.message + ' ' + policyErrorHint(payload.action, e.message);
    }
  }
}

function preparePolicyAction(action) {
  if (!requireAdminAction('Policy action')) {
    return;
  }
  const notesInput = document.getElementById('policyEditNotes');
  const notes = notesInput && notesInput.value.trim() ? notesInput.value.trim() : 'dashboard ' + action;
  const payload = { action: action, notes: notes };
  const targetGroup = policyInputValue('policyTargetGroup');
  const targetTag = policyInputValue('policyTargetTag');
  if (targetGroup) payload.target_group = targetGroup;
  if (targetTag) payload.target_tag = targetTag;
  if (action === 'rollback') {
    const currentVersion = latestPolicies && latestPolicies.current ? Number(latestPolicies.current.version || 0) : 0;
    const candidates = (latestPolicies.history || [])
      .map(item => Number(item.version || 0))
      .filter(version => version > 0 && version !== currentVersion)
      .sort((a, b) => b - a);
    if (candidates.length === 0) {
      const status = document.getElementById('policyActionStatus');
      if (status) {
        status.textContent = 'Rollback unavailable: no previous policy version';
      }
      return;
    }
    payload.target_version = candidates[0];
  }
  runPolicyAction(payload);
}

function policyInputValue(id) {
  const el = document.getElementById(id);
  return el && el.value ? el.value.trim() : '';
}

function loadExamplePolicyRule() {
  const ruleID = document.getElementById('policyRuleID');
  const ruleYAML = document.getElementById('policyRuleYAML');
  const notes = document.getElementById('policyEditNotes');
  if (ruleID) {
    ruleID.value = 'example-suspicious-shell';
  }
  if (ruleYAML) {
    ruleYAML.value = [
      'title: Suspicious Shell Execution',
      'id: example-suspicious-shell',
      'status: test',
      'description: Detects shells launched by sensitive services',
      'logsource:',
      '  product: linux',
      '  category: process_creation',
      'detection:',
      '  selection:',
      '    comm:',
      '      - sh',
      '      - bash',
      '      - zsh',
      '  condition: selection',
      'level: medium',
    ].join('\n');
  }
  if (notes && !notes.value.trim()) {
    notes.value = 'dashboard example sigma rule validation';
  }
  const status = document.getElementById('policyActionStatus');
  if (status) {
    status.textContent = 'Example Sigma rule loaded; run Validate Sigma before publishing.';
  }
}

function preparePolicyMutation(action) {
  if (!requireAdminAction('Policy mutation')) {
    return;
  }
  const notes = policyInputValue('policyEditNotes') || 'dashboard ' + action;
  const payload = { action: action, notes: notes };
  if (action.endsWith('_sigma')) {
    payload.rule_id = policyInputValue('policyRuleID');
    payload.rule_yaml = document.getElementById('policyRuleYAML') ? document.getElementById('policyRuleYAML').value : '';
  } else if (action.endsWith('_whitelist')) {
    payload.whitelist_target = policyInputValue('policyWhitelistTarget');
    payload.whitelist_value = policyInputValue('policyWhitelistValue');
  } else if (action.endsWith('_taint')) {
    payload.taint_prefix = policyInputValue('policyTaintPrefix');
    payload.taint_label = policyInputValue('policyTaintLabel');
  }
  const validation = validatePolicyMutationInput(action, payload);
  if (validation) {
    const status = document.getElementById('policyActionStatus');
    if (status) {
      status.textContent = validation;
    }
    return;
  }
  runPolicyAction(payload);
}

function validatePolicyMutationInput(action, payload) {
  if (action.endsWith('_sigma')) {
    if (!payload.rule_id) {
      return 'Rule ID is required before running ' + action + '.';
    }
    if ((action === 'add_sigma' || action === 'update_sigma' || action === 'validate_sigma') && !String(payload.rule_yaml || '').trim()) {
      return 'Rule YAML is required before running ' + action + '. Paste a Sigma rule with title and detection.condition.';
    }
  }
  if (action === 'add_whitelist' || action === 'remove_whitelist') {
    if (!payload.whitelist_target || !payload.whitelist_value) {
      return 'Whitelist target and value are required. Example: target comm, value backup-agent.';
    }
  }
  if (action === 'add_taint' || action === 'remove_taint') {
    if (!payload.taint_prefix) {
      return 'Taint prefix is required. Example: 10.0.0.0/8 or suspicious-source.';
    }
  }
  return '';
}

function policyErrorHint(action, message) {
  const text = String(message || '').toLowerCase();
  if (text.indexOf('rule_yaml') >= 0 || text.indexOf('sigma') >= 0) {
    return 'Check Sigma YAML syntax, title, detection block, and detection.condition.';
  }
  if (text.indexOf('approval') >= 0) {
    return 'Request approval in Compliance & SIEM before publishing or rolling back.';
  }
  if (text.indexOf('rule_id') >= 0) {
    return 'Enter a stable rule ID so policy history remains searchable.';
  }
  return 'Review the policy diff and control-plane audit log.';
}

function policySuccessMessage(action, result) {
  const version = result && result.version ? (' v' + result.version) : '';
  const state = result && result.state ? (' · ' + result.state) : '';
  const deployment = result && result.deployment_status ? (' · deployment ' + result.deployment_status) : '';
  if (action === 'validate_sigma' || action === 'dry_run_sigma') {
    return 'Sigma validation passed; draft unchanged' + version + state;
  }
  return 'Policy action completed' + version + state + deployment;
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
      '<button onclick="window.open(\'/api/v1/alerts/' + encodeURIComponent(traceID) + '/svg/view\', \'_blank\', \'noreferrer\')">Trace SVG</button>' +
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

function panelID(panel) {
  return (panel.dataset.panelId || '')
    || ((panel.querySelector('h2') || {}).textContent || 'panel').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function applyPanelOrder(order) {
  const content = document.querySelector('.content');
  if (!content) return;
  const panels = Array.from(content.querySelectorAll('.panel'));
  const byID = new Map(panels.map(panel => [panelID(panel), panel]));
  order.forEach(id => {
    const panel = byID.get(id);
    if (panel) content.appendChild(panel);
  });
  panels.forEach(panel => {
    if (!order.includes(panelID(panel))) content.appendChild(panel);
  });
}

function savePanelOrder() {
  const panels = Array.from(document.querySelectorAll('.content .panel'));
  localStorage.setItem('providaptDashboardPanelOrder', JSON.stringify(panels.map(panelID)));
  scheduleDashboardMasonry();
}

function panelSizeConfig(panel) {
  return {
    columns: Number(panel.dataset.resizeColumns || dashboardPanelDefaultColumns(panel)),
    minHeight: Number(panel.dataset.resizeMinHeight || 0),
    userSized: panel.dataset.userSized === 'true',
  };
}

function dashboardPanelDefaultColumns(panel) {
  const id = panelID(panel);
  if (panel && panel.dataset.defaultColumns) {
    return Math.max(1, Math.min(2, Number(panel.dataset.defaultColumns || 1)));
  }
  if (['alert-workflow', 'policy-center', 'agent-overview', 'operations-summary'].includes(id)) return 2;
  return 1;
}

function panelVisibleHeight(element) {
  if (!element) return 0;
  const rect = element.getBoundingClientRect();
  return Math.ceil(rect.height || element.scrollHeight || 0);
}

let dashboardMasonryTimer = null;

function dashboardGridNumber(value, fallback) {
  const parsed = Number.parseFloat(String(value || '').replace('px', ''));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function layoutDashboardMasonry() {
  const content = document.querySelector('.content');
  if (!content) return;
  const style = window.getComputedStyle ? window.getComputedStyle(content) : null;
  const rowHeight = dashboardGridNumber(style && style.gridAutoRows, 8);
  const gap = dashboardGridNumber(style && (style.rowGap || style.gap), 7);
  Array.from(content.querySelectorAll('.panel')).forEach(panel => {
    if (panel.classList.contains('section-hidden')) {
      panel.style.gridRowEnd = '';
      return;
    }
    panel.style.gridRowEnd = '';
    const naturalHeight = Math.ceil(panel.getBoundingClientRect().height || panel.scrollHeight || panelAdaptiveMinimumHeight(panel));
    const span = Math.max(1, Math.ceil((naturalHeight + gap) / (rowHeight + gap)));
    panel.style.gridRowEnd = 'span ' + span;
  });
}

function scheduleDashboardMasonry() {
  window.clearTimeout(dashboardMasonryTimer);
  dashboardMasonryTimer = window.setTimeout(() => {
    if (typeof window.requestAnimationFrame === 'function') {
      window.requestAnimationFrame(layoutDashboardMasonry);
    } else {
      layoutDashboardMasonry();
    }
  }, 0);
}

function panelAdaptiveMinimumHeight(panel) {
  if (!panel) return 140;
  const header = panel.querySelector('h2');
  const body = panel.querySelector('.panel-body');
  const headerHeight = panelVisibleHeight(header) || 38;
  if (!body) return headerHeight + 72;
  const children = Array.from(body.children).filter(child => {
    const style = window.getComputedStyle ? window.getComputedStyle(child) : null;
    return !style || style.display !== 'none';
  });
  const essentialChildren = children.slice(0, Math.min(children.length, 2));
  const essentialHeight = essentialChildren.reduce((total, child) => total + Math.min(panelVisibleHeight(child), 58), 0);
  const scrollReserve = body.querySelector('.alerts-list, .agents-list, .data-table-wrap') ? 44 : 0;
  const bodyPadding = 22;
  return Math.ceil(Math.max(128, headerHeight + essentialHeight + scrollReserve + bodyPadding));
}

function panelAdaptiveMaximumHeight(panel) {
  const floor = panelAdaptiveMinimumHeight(panel);
  return Math.max(floor + 160, Math.min(1100, Math.max(420, window.innerHeight - 96)));
}

function clearPanelSize(panel, columns) {
  if (!panel) return;
  const resolvedColumns = Math.max(1, Math.min(2, Number(columns || dashboardPanelDefaultColumns(panel))));
  delete panel.dataset.resizeColumns;
  delete panel.dataset.resizeMinHeight;
  delete panel.dataset.userSized;
  panel.classList.remove('user-sized');
  panel.style.removeProperty('--panel-user-height');
  panel.style.gridColumn = resolvedColumns > 1 ? 'span 2' : '';
  panel.style.minHeight = '';
  panel.style.height = '';
  panel.style.maxHeight = '';
  panel.style.gridRowEnd = '';
  const body = panel.querySelector('.panel-body');
  if (body) {
    body.style.height = '';
    body.style.minHeight = '';
    body.style.overflow = '';
  }
  const badge = panel.querySelector('.panel-size-badge');
  if (badge) badge.textContent = resolvedColumns + ' col · auto';
}

function applyPanelSize(panel, size, userSized) {
  if (!panel || !size) return;
  const columns = Math.max(1, Math.min(2, Number(size.columns || 1)));
  const requestedHeight = Number(size.minHeight || size.height || 360);
  const minHeight = Math.max(panelAdaptiveMinimumHeight(panel), Math.min(panelAdaptiveMaximumHeight(panel), requestedHeight));
  panel.dataset.resizeColumns = String(columns);
  panel.dataset.resizeMinHeight = String(minHeight);
  panel.dataset.userSized = userSized === false ? 'false' : 'true';
  panel.classList.toggle('user-sized', userSized !== false);
  panel.style.setProperty('--panel-user-height', minHeight + 'px');
  panel.style.gridColumn = columns > 1 ? 'span 2' : '';
  panel.style.minHeight = minHeight + 'px';
  panel.style.height = minHeight + 'px';
  panel.style.maxHeight = 'none';
  const body = panel.querySelector('.panel-body');
  if (body) {
    body.style.height = 'auto';
    body.style.minHeight = '0';
    body.style.overflow = 'auto';
  }
  const badge = panel.querySelector('.panel-size-badge');
  if (badge) badge.textContent = columns + ' col · ' + minHeight + 'px';
  scheduleDashboardMasonry();
}

function adaptivePanelHeight(panel) {
  if (!panel) return 360;
  const header = panel.querySelector('h2');
  const body = panel.querySelector('.panel-body');
  const headerHeight = header ? Math.ceil(header.getBoundingClientRect().height) : 38;
  const bodyContentHeight = body ? Math.ceil(body.scrollHeight) : Math.ceil(panel.scrollHeight - headerHeight);
  const viewportLimit = panelAdaptiveMaximumHeight(panel);
  const naturalHeight = headerHeight + bodyContentHeight + 28;
  return Math.max(panelAdaptiveMinimumHeight(panel), Math.min(viewportLimit, naturalHeight));
}

function applyAdaptivePanelSize(panel) {
  if (!panel) return;
  const resize = () => {
    applyPanelSize(panel, { columns: 2, minHeight: adaptivePanelHeight(panel) }, true);
    savePanelSizes();
  };
  if (typeof window.requestAnimationFrame === 'function') {
    window.requestAnimationFrame(resize);
  } else {
    resize();
  }
}

function savedPanelSizes() {
  try {
    return JSON.parse(localStorage.getItem('providaptDashboardPanelSizes') || '{}');
  } catch (e) {
    return {};
  }
}

function savePanelSizes() {
  const sizes = {};
  document.querySelectorAll('.content .panel').forEach(panel => {
    const size = panelSizeConfig(panel);
    if (size.userSized) sizes[panelID(panel)] = size;
  });
  localStorage.setItem('providaptDashboardPanelSizes', JSON.stringify(sizes));
}

function applyPanelSizes(sizes) {
  const allSizes = sizes || savedPanelSizes();
  document.querySelectorAll('.content .panel').forEach(panel => {
    const saved = allSizes[panelID(panel)];
    if (saved && saved.userSized === true) {
      applyPanelSize(panel, saved, true);
    } else {
      clearPanelSize(panel, dashboardPanelDefaultColumns(panel));
    }
  });
  scheduleDashboardMasonry();
}

function installPanelResize(panel) {
  if (!panel || panel.querySelector('.panel-resize-handle')) return;
  const handle = document.createElement('button');
  handle.type = 'button';
  handle.className = 'panel-resize-handle';
  handle.setAttribute('aria-label', 'Resize panel');
  handle.title = 'Drag to resize panel';
  const badge = document.createElement('span');
  badge.className = 'panel-size-badge';
  panel.appendChild(handle);
  panel.appendChild(badge);
  handle.addEventListener('pointerdown', event => {
    event.preventDefault();
    event.stopPropagation();
    handle.setPointerCapture && handle.setPointerCapture(event.pointerId);
    const content = document.querySelector('.content');
    const start = panelSizeConfig(panel);
    const startX = event.clientX;
    const startY = event.clientY;
    const startHeight = Math.round(panel.getBoundingClientRect().height || start.minHeight);
    const columnWidth = content ? Math.max(260, content.getBoundingClientRect().width / 2) : 420;
    panel.classList.add('resizing');
    document.body.classList.add('panel-resize-active');
    const onMove = moveEvent => {
      moveEvent.preventDefault();
      const deltaX = moveEvent.clientX - startX;
      const deltaY = moveEvent.clientY - startY;
      const columns = start.columns === 1 && deltaX > columnWidth * 0.35 ? 2 : (start.columns === 2 && deltaX < -columnWidth * 0.25 ? 1 : start.columns);
      const minHeight = Math.max(panelAdaptiveMinimumHeight(panel), Math.min(panelAdaptiveMaximumHeight(panel), startHeight + deltaY));
      applyPanelSize(panel, { columns: columns, minHeight: minHeight }, true);
    };
    const onUp = upEvent => {
      if (handle.releasePointerCapture && upEvent && upEvent.pointerId != null) {
        try { handle.releasePointerCapture(upEvent.pointerId); } catch (e) {}
      }
      panel.classList.remove('resizing');
      document.body.classList.remove('panel-resize-active');
      savePanelSizes();
      document.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerup', onUp);
      document.removeEventListener('pointercancel', onUp);
    };
    document.addEventListener('pointermove', onMove);
    document.addEventListener('pointerup', onUp);
    document.addEventListener('pointercancel', onUp);
  });
  handle.addEventListener('mousedown', event => {
    if (window.PointerEvent) return;
    event.preventDefault();
    event.stopPropagation();
    const content = document.querySelector('.content');
    const start = panelSizeConfig(panel);
    const startX = event.clientX;
    const startY = event.clientY;
    const startHeight = Math.round(panel.getBoundingClientRect().height || start.minHeight);
    const columnWidth = content ? Math.max(260, content.getBoundingClientRect().width / 2) : 420;
    panel.classList.add('resizing');
    document.body.classList.add('panel-resize-active');
    const onMove = moveEvent => {
      moveEvent.preventDefault();
      const deltaX = moveEvent.clientX - startX;
      const deltaY = moveEvent.clientY - startY;
      const columns = start.columns === 1 && deltaX > columnWidth * 0.35 ? 2 : (start.columns === 2 && deltaX < -columnWidth * 0.25 ? 1 : start.columns);
      const minHeight = Math.max(panelAdaptiveMinimumHeight(panel), Math.min(panelAdaptiveMaximumHeight(panel), startHeight + deltaY));
      applyPanelSize(panel, { columns: columns, minHeight: minHeight }, true);
    };
    const onUp = () => {
      panel.classList.remove('resizing');
      document.body.classList.remove('panel-resize-active');
      savePanelSizes();
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
  handle.addEventListener('dblclick', event => {
    event.preventDefault();
    event.stopPropagation();
    applyAdaptivePanelSize(panel);
  });
}

function dashboardPanelSection(panel) {
  const id = panelID(panel);
  if (['operations-summary'].includes(id)) return 'all';
  if (['policy-center', 'alert-workflow', 'evaluation-ground-truth'].includes(id)) return 'detect';
  if (['investigation-console'].includes(id)) return 'investigate';
  if (['support-bundle', 'backup-restore', 'delivery-health'].includes(id)) return 'respond';
  if (['control-plane-summary', 'agent-overview', 'deployment-diagnostics'].includes(id)) return 'platform';
  if (['compliance-siem', 'version-update'].includes(id)) return 'govern';
  return 'platform';
}

function dashboardPanelSectionShortLabel(section) {
  return {
    all: 'OVERVIEW',
    detect: 'ALERTS',
    investigate: 'TRACE',
    respond: 'RESPOND',
    platform: 'PLATFORM',
    govern: 'RELEASE',
  }[section] || 'MODULE';
}

function ensurePanelHeaderMeta(panel) {
  if (!panel) return;
  const header = panel.querySelector('h2');
  if (!header) return;
  const section = panel.dataset.section || dashboardPanelSection(panel);
  let chip = header.querySelector('.panel-section-chip');
  if (!chip) {
    chip = document.createElement('span');
    chip.className = 'panel-section-chip';
    header.appendChild(chip);
  }
  chip.textContent = dashboardPanelSectionShortLabel(section);
}

function normalizeDashboardPanelStructure(panel) {
  if (!panel) return;
  const body = panel.querySelector('.panel-body');
  const hasSummary = !!(body && body.querySelector('.policy-grid, .mini-metrics, .delivery-summary, .module-quality-grid, .workflow-summary-grid'));
  const hasToolbar = !!(body && body.querySelector('.action-row, .console-toolbar, .fleet-toolbar, .ground-truth-toolbar, .workflow-filter-bar, .policy-editor'));
  const hasList = !!(body && body.querySelector('.alerts-list, .agents-list, .data-table-wrap'));
  panel.classList.toggle('has-summary', hasSummary);
  panel.classList.toggle('has-toolbar', hasToolbar);
  panel.classList.toggle('has-list', hasList);
}

function normalizeDashboardPanels() {
  document.querySelectorAll('.content .panel').forEach(panel => normalizeDashboardPanelStructure(panel));
  scheduleDashboardMasonry();
}

function dashboardSectionLabel(section) {
  return {
    all: 'Overview: live health, alerts, response status, and platform readiness.',
    detect: 'Alerts: rule lifecycle, triage queue, analyst labels, and detection quality.',
    investigate: 'Investigate: provenance graph, event timeline, node drilldown, and reports.',
    respond: 'Respond: case actions, notification delivery, support bundle, and recovery.',
    platform: 'Platform: fleet health, kernel attachment, API security, storage, and runtime.',
    govern: 'Release: compliance, SIEM, upgrade, and release evidence.',
    operations: 'Platform: fleet health, deployment diagnostics, and posture summary.',
    detection: 'Detect: policies, alert workflow, ground truth, and investigation.',
    evidence: 'Respond: support bundles, backup/restore, and delivery health.',
  }[section] || 'Dashboard view updated.';
}

function updateDashboardSectionTabs(section) {
  document.querySelectorAll('[data-dashboard-section]').forEach(button => {
    const active = button.dataset.dashboardSection === section;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  const hint = document.getElementById('workspaceHint');
  if (hint) hint.textContent = dashboardSectionLabel(section);
}

function switchDashboardSection(section) {
  const aliases = { operations: 'platform', detection: 'detect', evidence: 'respond' };
  const selected = aliases[section] || section || 'all';
  localStorage.setItem('providaptDashboardSection', selected);
  document.querySelectorAll('.content .panel').forEach(panel => {
    const panelSection = dashboardPanelSection(panel);
    const visible = selected === 'all' || panelSection === selected || panelSection === 'all';
    panel.classList.toggle('section-hidden', !visible);
  });
  updateDashboardSectionTabs(selected);
  scheduleDashboardMasonry();
}

function setDashboardDensity(density) {
  const selected = ['compact', 'comfortable'].includes(density) ? density : 'standard';
  document.body.classList.remove('dashboard-density-compact', 'dashboard-density-comfortable');
  if (selected !== 'standard') {
    document.body.classList.add('dashboard-density-' + selected);
  }
  localStorage.setItem('providaptDashboardDensity', selected);
  const hint = document.getElementById('workspaceHint');
  if (hint) hint.textContent = 'Dashboard density set to ' + selected + '.';
  scheduleDashboardMasonry();
}

function setDashboardTheme(theme) {
  const selected = theme === 'contrast' ? 'contrast' : 'dark';
  document.body.classList.toggle('dashboard-theme-contrast', selected === 'contrast');
  localStorage.setItem('providaptDashboardTheme', selected);
  const hint = document.getElementById('workspaceHint');
  if (hint) hint.textContent = 'Dashboard theme set to ' + selected + '.';
}

function saveDashboardViewProfile() {
  const profile = {
    schema: 'providapt.dashboard_view_profile.v1',
    layout_version: DASHBOARD_LAYOUT_VERSION,
    saved_at: new Date().toISOString(),
    section: localStorage.getItem('providaptDashboardSection') || 'all',
    density: localStorage.getItem('providaptDashboardDensity') || 'standard',
    theme: localStorage.getItem('providaptDashboardTheme') || 'dark',
    panel_order: JSON.parse(localStorage.getItem('providaptDashboardPanelOrder') || '[]'),
    panel_sizes: savedPanelSizes(),
    workflow_filters: collectAlertWorkflowFilters(),
  };
  localStorage.setItem('providaptDashboardViewProfile', JSON.stringify(profile));
  openDetailDrawer('Dashboard View Saved', 'User-specific layout, density, theme, and filters', renderJSONBlock(profile));
}

function loadDashboardViewProfile() {
  try {
    const profile = JSON.parse(localStorage.getItem('providaptDashboardViewProfile') || '{}');
    if (!profile || !profile.schema) {
      openDetailDrawer('Dashboard View Profile', 'No saved profile found', renderEmptyDiagnostic('No saved view profile', ['Use Save View after arranging panels and filters.']));
      return;
    }
    const compatible = profile.layout_version === DASHBOARD_LAYOUT_VERSION;
    if (compatible && profile.panel_order && profile.panel_order.length) applyPanelOrder(profile.panel_order);
    if (compatible && profile.panel_sizes) applyPanelSizes(profile.panel_sizes);
    setDashboardDensity(profile.density || 'standard');
    setDashboardTheme(profile.theme || 'dark');
    switchDashboardSection(profile.section || 'all');
    const filters = profile.workflow_filters || {};
    Object.keys(filters).forEach(key => {
      const id = 'workflowFilter' + key.charAt(0).toUpperCase() + key.slice(1);
      const element = document.getElementById(id);
      if (element) element.value = filters[key] || '';
    });
    applyAlertWorkflowFilters();
    scheduleDashboardMasonry();
    openDetailDrawer('Dashboard View Loaded', compatible ? 'Restored saved analyst workspace profile' : 'Loaded theme/filters only; old layout was reset', renderJSONBlock(profile));
  } catch (e) {
    setInvestigationLoading('Dashboard view profile load failed: ' + e.message);
  }
}

function resetDashboardLayout() {
  localStorage.removeItem('providaptDashboardPanelOrder');
  localStorage.removeItem('providaptDashboardPanelSizes');
  localStorage.removeItem('providaptDashboardViewProfile');
  localStorage.setItem('providaptDashboardLayoutVersion', DASHBOARD_LAYOUT_VERSION);
  localStorage.setItem('providaptDashboardSection', 'all');
  applyPanelOrder(defaultDashboardPanelOrder());
  applyPanelSizes({});
  switchDashboardSection('all');
  setDashboardDensity('standard');
  scheduleDashboardMasonry();
}

function defaultDashboardPanelOrder() {
  return [
    'control-plane-summary',
    'operations-summary',
    'alert-workflow',
    'policy-center',
    'investigation-console',
    'evaluation-ground-truth',
    'delivery-health',
    'support-bundle',
    'backup-restore',
    'agent-overview',
    'deployment-diagnostics',
    'compliance-siem',
  ];
}

function initializePanelLayout() {
  const content = document.querySelector('.content');
  if (!content) return;
  const defaultOrder = defaultDashboardPanelOrder();
  Array.from(content.querySelectorAll('.panel')).forEach(panel => {
    panel.dataset.panelId = panelID(panel);
    panel.dataset.section = dashboardPanelSection(panel);
    panel.classList.add('dashboard-panel');
    ensurePanelHeaderMeta(panel);
    normalizeDashboardPanelStructure(panel);
    installPanelResize(panel);
    const header = panel.querySelector('h2');
    if (!header) return;
    header.setAttribute('draggable', 'true');
    header.addEventListener('dragstart', event => {
      panel.classList.add('dragging');
      event.dataTransfer.setData('text/plain', panel.dataset.panelId);
      event.dataTransfer.effectAllowed = 'move';
    });
    header.addEventListener('dragend', () => {
      panel.classList.remove('dragging');
      Array.from(content.querySelectorAll('.drag-over')).forEach(item => item.classList.remove('drag-over'));
      savePanelOrder();
      scheduleDashboardMasonry();
    });
    panel.addEventListener('dragover', event => {
      event.preventDefault();
      panel.classList.add('drag-over');
    });
    panel.addEventListener('dragleave', () => panel.classList.remove('drag-over'));
    panel.addEventListener('drop', event => {
      event.preventDefault();
      panel.classList.remove('drag-over');
      const draggedID = event.dataTransfer.getData('text/plain');
      const dragged = content.querySelector('[data-panel-id="' + draggedID + '"]');
      if (!dragged || dragged === panel) return;
      const rect = panel.getBoundingClientRect();
      const placeAfter = event.clientY > rect.top + rect.height / 2;
      content.insertBefore(dragged, placeAfter ? panel.nextSibling : panel);
      savePanelOrder();
      scheduleDashboardMasonry();
    });
  });
  try {
    const saved = JSON.parse(localStorage.getItem('providaptDashboardPanelOrder') || '[]');
    applyPanelOrder(saved.length ? saved : defaultOrder);
  } catch (e) {
    applyPanelOrder(defaultOrder);
  }
  applyPanelSizes();
  setDashboardDensity(localStorage.getItem('providaptDashboardDensity') || 'standard');
  setDashboardTheme(localStorage.getItem('providaptDashboardTheme') || 'dark');
  switchDashboardSection(localStorage.getItem('providaptDashboardSection') || 'all');
  scheduleDashboardMasonry();
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
