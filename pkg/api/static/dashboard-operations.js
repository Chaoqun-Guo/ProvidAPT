// Dashboard operations summary rendering.
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
