// Dashboard fleet inventory, enrollment, and environment actions.
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
      list.innerHTML = '<div class="loading">No agents reporting yet. Start an agent, confirm telemetry endpoint, then refresh this panel.</div>';
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
        const certLabel = certFingerprint ? (certFingerprint.length > 23 ? certFingerprint.slice(0, 23) + '...' : certFingerprint) : '--';
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
      ' · cert ' + escapeHTML(agent.cert_fingerprint ? agent.cert_fingerprint.slice(0, 23) + '...' : '--') +
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
