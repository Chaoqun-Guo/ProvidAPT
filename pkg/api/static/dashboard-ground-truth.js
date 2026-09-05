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

function showModelHealthDashboard() {
  const alertMetrics = computeAlertQuality(latestWorkflow.alerts || []);
  const coverage = buildGroundTruthCoverage();
  const actionable = alertMetrics.true_positive + alertMetrics.false_positive + alertMetrics.benign;
  const recall = coverage.malicious ? Number((coverage.detected * 100 / coverage.malicious).toFixed(1)) : 0;
  const precision = alertMetrics.actionable_precision_percent || 0;
  const f1 = precision + recall ? Number((2 * precision * recall / (precision + recall)).toFixed(1)) : 0;
  const modelHealth = {
    schema: 'providapt.dashboard_model_health.v1',
    metrics: {
      precision_percent: precision,
      recall_percent: recall,
      f1_percent: f1,
      review_coverage_percent: alertMetrics.review_coverage_percent || 0,
      duplicate_percent: alertMetrics.duplicate_percent || 0,
    },
    governance_bindings: {
      training_data: latestGroundTruth.files && latestGroundTruth.files.length ? 'loaded' : 'missing local/server evidence',
      feature_schema: 'required in model-lifecycle-gate',
      model_artifact: 'required in model-lifecycle-gate',
      promotion_approval: 'required before promotion',
      rollback: 'required in governance bindings',
    },
  };
  const cards = '<div class="model-governance-grid">' + [
    ['Precision', precision + '%', alertMetrics.true_positive + ' TP / ' + actionable + ' reviewed actionable'],
    ['Recall', recall + '%', coverage.detected + '/' + coverage.malicious + ' malicious covered'],
    ['F1', f1 + '%', 'balanced promotion signal'],
    ['Review', alertMetrics.review_coverage_percent + '%', alertMetrics.reviewed_alerts + '/' + alertMetrics.total_alerts + ' alerts reviewed'],
  ].map(row => '<div class="matrix-card"><div class="label">' + escapeHTML(row[0]) + '</div><div class="value">' + escapeHTML(row[1]) + '</div><div class="sub">' + escapeHTML(row[2]) + '</div></div>').join('') + '</div>';
  const governanceRows = [
    { item: 'Training data', state: modelHealth.governance_bindings.training_data, evidence: 'dataset manifest hash' },
    { item: 'Feature schema', state: modelHealth.governance_bindings.feature_schema, evidence: 'schema hash' },
    { item: 'Model artifact', state: modelHealth.governance_bindings.model_artifact, evidence: 'artifact hash' },
    { item: 'Promotion approval', state: modelHealth.governance_bindings.promotion_approval, evidence: 'model owner, security, SOC lead' },
    { item: 'Rollback', state: modelHealth.governance_bindings.rollback, evidence: 'rollback target and artifact hash' },
  ];
  const table = renderDataTable([
    { key: 'item', label: 'Binding' },
    { key: 'state', label: 'State' },
    { key: 'evidence', label: 'Evidence' },
  ], governanceRows, 'No model governance bindings available');
  openDetailDrawer('Model Health', 'Model quality and promotion governance bindings', cards + table + renderJSONBlock(modelHealth));
  setInvestigationItems(governanceRows.map(row => renderKVItem(row.item, row.state, row.evidence)), 'No model health evidence available');
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
    ? '<button class="secondary" onclick="openTraceViewer(\'' + jsString(nodeID) + '\')">Open Trace</button>'
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
