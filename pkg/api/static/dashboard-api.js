let lastAPIRequest = null;

async function fetchJSON(url, options) {
  const opts = options || {};
  const suppressAuthError = opts.quietAuth || isBackgroundProtectedRead(url);
  rememberLastRequest('GET', url);
  try {
    const r = await fetch(url, { headers: requestHeaders() });
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
    headers: Object.assign({ 'Content-Type': 'application/json' }, requestHeaders()),
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
    const err = new Error(authz ? 'Request blocked by the running daemon' : sanitizeAPIErrorText(data.error || response.statusText));
    err.status = response.status;
    err.url = url;
    if (!authz) reportAPIError('POST', url, err);
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
  const r = await fetch(url, { headers: requestHeaders() });
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
    err.message = 'Request blocked by the running daemon';
  } else {
    err.message = sanitizeAPIErrorText(err.message);
  }
  return err;
}

function reportAPIError(method, url, err) {
  if (isAuthzError(err)) return;
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
    return 'Request blocked by the running daemon';
  }
  const message = err && err.message ? err.message : 'request failed';
  return sanitizeAPIErrorText(message);
}

function sanitizeAPIErrorText(message) {
  return String(message || 'request failed')
    .replace(/credential/ig, 'access setting');
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

function apiErrorHint(err) {
  if (err && (err.status === 401 || err.status === 403)) {
    return 'Upgrade the running daemon to the open-source control-plane build.';
  }
  if (err && err.status === 404) {
    return 'Confirm the endpoint is available in this build.';
  }
  if (err && err.status === 409) {
    return 'Retry against the active control-plane leader.';
  }
  return 'Check daemon health, network access, and server logs.';
}

function requestHeaders() {
  return {};
}

function updateAPIStatus(message) {
  const status = document.getElementById('actionStatus');
  if (status && message) status.textContent = message;
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

async function openProtectedEndpoint(url, defaultName) {
  rememberLastRequest('DOWNLOAD', url, { file_name: defaultName || 'providapt-response' });
  try {
    const response = await fetch(url, { headers: requestHeaders() });
    if (!response.ok) {
      const err = await responseError(response, url);
      reportAPIError('GET', url, err);
      updateAPIStatus('Open failed: ' + friendlyAPIErrorMessage(err));
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
  const response = await fetch(url, { headers: requestHeaders() });
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
