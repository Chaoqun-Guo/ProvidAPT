// Dashboard panel ordering, resizing, section switching, and view profile controls.
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
    platform: 'FLEET',
    govern: 'EVIDENCE',
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
  const tier = dashboardPanelTier(panel);
  panel.dataset.tier = tier;
  panel.classList.toggle('tier-secondary', tier === 'secondary');
}

function normalizeDashboardPanels() {
  document.querySelectorAll('.content .panel').forEach(panel => normalizeDashboardPanelStructure(panel));
  scheduleDashboardMasonry();
}

function dashboardSectionLabel(section) {
  return {
    all: 'Overview: live health, open alerts, fleet posture, and next actions.',
    detect: 'Alerts: policy rules, triage queue, analyst labels, and detection quality.',
    investigate: 'Investigate: provenance graph, event timeline, node drilldown, and reports.',
    respond: 'Respond: case actions, delivery health, support bundle, and recovery.',
    platform: 'Fleet: agent health, kernel attachment, API mode, storage, and runtime.',
    govern: 'Evidence: compliance, SIEM, upgrade, and release records.',
    operations: 'Fleet: agent health, deployment diagnostics, and posture summary.',
    detection: 'Alerts: policies, triage, ground truth, and investigation.',
    evidence: 'Evidence: support bundles, backup/restore, delivery health, and release records.',
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
    const visible = selected === 'all'
      ? dashboardOverviewPanelIDs().includes(panelID(panel))
      : panelSection === selected || panelSection === 'all';
    panel.classList.toggle('section-hidden', !visible);
  });
  updateDashboardSectionTabs(selected);
  scheduleDashboardMasonry();
}

function dashboardOverviewPanelIDs() {
  return [
    'operations-summary',
    'alert-workflow',
    'investigation-console',
    'agent-overview',
  ];
}

function dashboardPanelTier(panel) {
  const id = panelID(panel);
  return [
    'support-bundle',
    'backup-restore',
    'delivery-health',
    'compliance-siem',
    'version-update',
    'evaluation-ground-truth',
  ].includes(id) ? 'secondary' : 'primary';
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
    'operations-summary',
    'alert-workflow',
    'investigation-console',
    'agent-overview',
    'policy-center',
    'control-plane-summary',
    'deployment-diagnostics',
    'evaluation-ground-truth',
    'delivery-health',
    'support-bundle',
    'backup-restore',
    'compliance-siem',
    'version-update',
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
