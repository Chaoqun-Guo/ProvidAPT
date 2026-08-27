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

async function runUpgradeAction(payload) {
  const status = document.getElementById('upgradeActionStatus');
  if (status) {
    status.textContent = 'Running ' + payload.action + '...';
  }
  try {
    const result = await postJSON('/api/v1/control/upgrade', payload);
    latestUpgrade = Object.assign({}, latestUpgrade || {}, result || {});
    if (status) {
      status.textContent = result.message || result.status || ('Upgrade action completed: ' + payload.action);
    }
    await loadUpgradeStatus();
    showUpgradeDetails();
  } catch (e) {
    if (status) {
      status.textContent = 'Upgrade action failed: ' + e.message;
    }
  }
}
