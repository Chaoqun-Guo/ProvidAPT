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
