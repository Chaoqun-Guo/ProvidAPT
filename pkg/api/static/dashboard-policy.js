// Dashboard policy center loader, drilldowns, and policy actions.
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
