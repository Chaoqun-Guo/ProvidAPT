package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func dashboardHTMLDocument() string {
	return dashboardHTML
}

func dashboardTestSurface() string {
	return dashboardHTML + "\n" + dashboardCSS + "\n" + dashboardResponsiveCSS + "\n" + dashboardJS
}

func TestDashboardAlertWorkflowSeparators(t *testing.T) {
	if strings.Contains(dashboardTestSurface(), " \u8def ") {
		t.Fatal("alert workflow dashboard should not render mojibake separators")
	}
	if !strings.Contains(dashboardTestSurface(), " · ") {
		t.Fatal("alert workflow dashboard should render readable separators")
	}
}

func TestDashboardAlertWorkflowTraceLinks(t *testing.T) {
	expected := []string{
		"function alertTraceActions",
		"/api/v1/alerts/",
		"/svg",
		"/api/v1/graph/node/",
		"/backward?depth=8",
		"/forward?depth=8",
		"/api/v1/events/search?pattern=",
		"Trace SVG",
		"showAlertEvents",
		"Open Events",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("alert workflow dashboard missing trace link content %q", item)
		}
	}
}

func TestDashboardAgentMonitoringFields(t *testing.T) {
	expected := []string{
		"last_report_age_seconds",
		"status_reason",
		"Report age:",
		".status-badge.offline",
		".status-badge.stale",
		"updateFleetAggregateMetrics",
		"graph_nodes",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing agent monitoring content %q", item)
		}
	}
}

func TestDashboardInvestigationConsole(t *testing.T) {
	forbidden := []string{
		"Provenance Graph",
		"graph-container",
		"cytoscape",
		"loadGraph",
		"Recent Alerts",
		"alertsList",
		"loadAlerts",
	}
	for _, item := range forbidden {
		if strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard should not render main provenance graph content %q", item)
		}
	}

	expected := []string{
		"Investigation Console",
		"Operations Summary",
		"opFleet",
		"opWorkflow",
		"opDelivery",
		"opEvidence",
		"loadOperationsSummary",
		"showGraphSummary('nodes')",
		"showGraphSummary('edges')",
		"graphClusterRows",
		"renderGraphClusterRows",
		"collapseGraphCluster",
		"graphTopHubs",
		"high-degree hub",
		"showRecentEvents()",
		"showDroppedEvents()",
		"showRuntimeDetails",
		"class=\"card clickable\"",
		"/api/v1/events/recent?limit=50",
		"/api/v1/graph/export",
		"investigationNodeInput",
		"showInvestigationReport",
		"downloadInvestigationReport",
		"/api/v1/investigation/report?",
		"showEventDetailsJSON",
		"eventDetailRows",
		"raw.schema_version",
		"installInteractionFeedback",
		"interactionFeedback",
		"action-clicked",
		"function setCompactVersionText",
		"setCompactVersionText('topVersion'",
		"overflow-x: hidden",
		"min-width:0",
		"repeat(auto-fit, minmax(120px, 1fr))",
		"flex: 1 1 160px",
		"text-overflow:ellipsis",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing investigation console content %q", item)
		}
	}
}

func TestDashboardResponsiveOverflowGuards(t *testing.T) {
	expected := []string{
		".platform-header",
		"flex-wrap: wrap",
		".header-right",
		"flex: 1 1 420px",
		"flex-wrap: wrap",
		"max-width: 118px",
		".alert-msg",
		"overflow-wrap: anywhere",
		".delivery-inline-actions button",
		"max-width: 160px",
		"display: none",
		`.dashboard-panel[data-panel-id="module-quality-review"] .module-quality-grid`,
		"minmax(min(100%, 168px), 1fr)",
		`.dashboard-panel[data-panel-id="module-quality-review"] .quality-card .quality-name`,
		"white-space: normal",
		".dashboard-panel .action-row button",
		".dashboard-panel .workflow-filter-bar",
		"minmax(min(100%, 112px), 1fr)",
		"overflow-wrap: anywhere",
		"@media (max-width: 1279px)",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardResponsiveCSS, item) {
			t.Fatalf("dashboard responsive CSS missing overflow guard %q", item)
		}
	}
}

func TestDashboardOpenSourceHeaderHasNoKeyPanel(t *testing.T) {
	forbidden := []string{
		"grid-template-columns: minmax(190px, 1fr) repeat(5, minmax(72px, max-content))",
		"grid-template-columns: minmax(180px, 1fr) repeat(3, minmax(72px, max-content))",
		"min-width:160px",
		"auth-strip",
		"apiKeyInput",
		"providapt_api_key",
	}
	for _, item := range forbidden {
		if strings.Contains(dashboardTestSurface(), item) || strings.Contains(dashboardResponsiveCSS, item) {
			t.Fatalf("open-source dashboard should not contain key-panel artifact %q", item)
		}
	}

	expected := []string{
		"Open-source build ready",
		"openUpgradePage",
		"@media (max-width: 760px)",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) && !strings.Contains(dashboardResponsiveCSS, item) {
			t.Fatalf("open-source dashboard missing compact header rule %q", item)
		}
	}
}

func TestDashboardOpenSourceBuildRemovesRemovedControlPlaneFeatures(t *testing.T) {
	forbidden := []string{
		"activ" + "ation",
		"Activ" + "ation",
		"lic" + "ense",
		"Lic" + "ense",
		"apiKey",
		"API Key",
		"X-API-Key",
		"missing or invalid api key",
		"missing or invalid API key",
		"/api/v1/control/" + "lic" + "ense",
	}
	for _, item := range forbidden {
		if strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("open-source dashboard should not contain %q", item)
		}
	}
}

func TestDashboardSanitizesAuthErrors(t *testing.T) {
	expected := []string{
		"friendlyAPIErrorMessage",
		"sanitizeAPIErrorText",
		"Access denied by local API policy",
		"'api' + '\\\\s+' + 'key'",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing auth error sanitizer content %q", item)
		}
	}
}

func TestDashboardModuleActions(t *testing.T) {
	forbidden := []string{
		"window.prompt",
		"prompt(",
		"window.alert",
		"alert(",
		"coming soon",
		"not implemented",
	}
	for _, item := range forbidden {
		if strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard should not contain placeholder interaction %q", item)
		}
	}

	expected := []string{
		"showFleetStatus('degraded')",
		"showAgentDetails",
		"applyFleetInputs",
		"markAgentReviewed",
		"setAgentEnrollment",
		"Enrollment:",
		"Cert:",
		"cert_fingerprint",
		"showSupportDetails('history')",
		"Backup & Restore",
		"runBackupAction('create')",
		"runBackupAction('restore_staging')",
		"runBackupAction('prepare_cutover')",
		"downloadBackupArchive",
		"/api/v1/control/backup",
		"Deployment Diagnostics",
		"diagAttachment",
		"diagAPI",
		"diagPolicy",
		"diagStorage",
		"renderDeploymentDiagnostics",
		"showDeploymentDiagnostics('attachment')",
		"showDeploymentDiagnostics('api')",
		"showDeploymentDiagnostics('policy')",
		"showDeploymentDiagnostics('storage')",
		"kernel_attachment_mode",
		"control_plane_state_backend",
		"topVersion",
		"Version Update",
		"providaptDashboardPanelOrder",
		"initializePanelLayout",
		"dashboard-panel",
		"drag-over",
		"grid-auto-rows",
		"showPolicyDetails('history')",
		"policyEditNotes",
		"preparePolicyMutation('validate_sigma')",
		"policyTargetGroup",
		"policyTargetTag",
		"Publish Draft",
		"Browse Rules",
		"Show Diff",
		"data.diff",
		"loadAlertWorkflowFiltered('open')",
		"runAlertWorkflowAction('assign'",
		"runAlertWorkflowAction('silence'",
		"runAlertWorkflowAction('close'",
		"data-module=\\\"alert-workflow\\\" data-module-action=\\\"close\\\"",
		"data-ui-close=\"detail-drawer\"",
		"onclick=\"closeDetailDrawer(event)\"",
		"moduleStatusTargets",
		"setModuleStatus('alert-workflow'",
		"runAlertWorkflowBulkAction('close')",
		"runAlertWorkflowBulkAction('silence')",
		"showAlertQuality()",
		"downloadAlertQuality()",
		"filterAlertQuality('duplicate')",
		"filterAlertQuality('needs_review')",
		"providapt.alert_quality.dashboard.v1",
		"review_coverage_percent",
		"actionable_precision_percent",
		"sla_status",
		"showDeliveriesByStatus('dead_letter')",
		"showDeliveryRisk('channels')",
		"showDeliveryRisk('tickets')",
		"showDeliveryRisk('errors')",
		"alertTraceActions(a)",
		"Compliance & SIEM",
		"loadCompliance",
		"runComplianceAction('export_audit')",
		"runComplianceAction('apply_retention')",
		"runComplianceAction('generate_report')",
		"runComplianceAction('generate_report', 'html')",
		"runComplianceAction('generate_report', 'bundle')",
		"runApprovalAction",
		"runComplianceAction('test_siem')",
		"native connector",
		"readiness",
		"prepareUpgradeAction('discover')",
		"data-module=\"version-update\"",
		"Release manifest URL",
		"prepareUpgradeAction('apply')",
		"prepareUpgradeAction('rollback')",
		"/api/v1/control/compliance",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing module action %q", item)
		}
	}
}

func TestDashboardDetailDrawerIsolation(t *testing.T) {
	expected := []string{
		"role=\"dialog\"",
		"aria-modal=\"true\"",
		"aria-labelledby=\"detailDrawerTitle\"",
		"aria-describedby=\"detailDrawerSubtitle\"",
		"id=\"detailDrawerClose\"",
		"id=\"detailDrawer\" class=\"detail-drawer\"",
		"hidden>",
		"function openDetailDrawer",
		"function closeDetailDrawer(event)",
		"detailDrawerHideTimer",
		"window.clearTimeout(detailDrawerHideTimer)",
		"drawer.hidden = false",
		"backdrop.hidden = false",
		"drawer.hidden = true",
		"backdrop.hidden = true",
		"position: fixed !important",
		"visibility: hidden",
		"pointer-events: none",
		"document.body.classList.add('detail-drawer-open')",
		"document.body.classList.remove('detail-drawer-open')",
		"body.detail-drawer-open",
		"body.innerHTML = bodyHTML",
		"body.scrollTop = 0",
		"classifyDashboardButtons();",
		"closeButton.focus",
		"detail-drawer-body button",
		"button.dataset.actionKind = kind",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing detail drawer isolation content %q", item)
		}
	}
}

func TestDashboardPolicyCenterWorkbenchLayout(t *testing.T) {
	expected := []string{
		"policy-center-panel",
		"policy-summary-grid",
		"policy-view-actions",
		"policy-center-editor",
		"policy-notes",
		"policy-rule-fields",
		"policy-yaml",
		"policy-rule-actions",
		"policy-publish-actions",
		"grid-template-areas:",
		"renderDetailSection('Policy Summary'",
		"renderDetailSection('Selected View'",
		"renderDetailSection('Raw Evidence'",
		"renderMetricCards",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing policy center workbench layout content %q", item)
		}
	}
}

func TestDashboardSemanticButtonClasses(t *testing.T) {
	expected := []string{
		"function classifyDashboardButtons",
		"function semanticButtonTitle",
		"btn-primary",
		"btn-danger",
		"btn-download",
		"btn-warning",
		"btn-refresh",
		"btn-disabled-context",
		"High-impact action: review scope before running",
		"State-changing action",
		"Export or download evidence",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing semantic button class content %q", item)
		}
	}
}

func TestDashboardCyberIDSTheme(t *testing.T) {
	expected := []string{
		"--ids-bg-0",
		"--ids-cyan",
		"--ids-red",
		"--ids-amber",
		"--ids-green",
		"glassmorphism",
		"radial-gradient(circle at 12% 10%",
		"backdrop-filter: blur(14px)",
		"text-shadow: 0 0 18px",
		"Electric Red",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing cyber IDS theme content %q", item)
		}
	}
}

func TestDashboardModuleScopedActions(t *testing.T) {
	expected := []string{
		"data-module=\"support\" data-module-action=\"export\"",
		"data-module=\"backup\" data-module-action=\"create\"",
		"data-module=\"policy-center\" data-module-action=\"publish\"",
		"data-module=\"delivery-health\" data-module-action=\"replay-all\"",
		"data-module=\"compliance-siem\" data-module-action=\"export-audit\"",
		"data-module=\"alert-workflow\" data-module-action=\"bulk-close\"",
		"data-module=\"version-update\" data-module-action=\"discover\"",
		"hasAttribute('data-ui-close')",
		"moduleName + ': ' + moduleAction",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing module-scoped action content %q", item)
		}
	}
}

func TestDashboardGroundTruthPanel(t *testing.T) {
	expected := []string{
		"Evaluation Ground Truth",
		"groundTruthFile",
		"loadGroundTruthFromFile",
		"loadGroundTruth",
		"showGroundTruthCorrelation",
		"showGroundTruthCoverage",
		"downloadGroundTruthDataset('labels')",
		"downloadGroundTruthDataset('coverage')",
		"downloadGroundTruthDataset('manifest')",
		"providapt.evaluation_dataset.v1",
		"providapt.attack_coverage.v1",
		"/api/v1/evaluation/ground-truth?limit=500",
		"/api/v1/evaluation/correlation?limit=200",
		"Server ground truth requires local API access. Use Load Local JSONL for local evidence files.",
		"Server correlation requires local API access; using browser-loaded ground truth when available.",
		"parseGroundTruthJSONL",
		"renderGroundTruthRecord",
		"renderGroundTruthCorrelation",
		"filterGroundTruth('malicious')",
		"gtMalicious",
		"gtBenign",
		"groundTruthPhaseGrid",
		"file-picker",
		"groundTruthFileName",
		"updateGroundTruthFileName",
		"onchange=\"updateGroundTruthFileName()\"",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing ground truth content %q", item)
		}
	}
}

func TestDashboardAlertAnnotationButtons(t *testing.T) {
	expected := []string{
		"runAlertWorkflowAction('annotate_tp'",
		"runAlertWorkflowAction('annotate_fp'",
		"payload.classification",
		"true_positive",
		"false_positive",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing alert annotation content %q", item)
		}
	}
}

func TestDashboardAdminActionsGiveFeedback(t *testing.T) {
	forbidden := []string{
		"if (currentRole !== 'admin') {\n    return;\n  }",
		"if (currentRole !== 'admin') return;",
	}
	for _, item := range forbidden {
		if strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard has silent admin guard %q", item)
		}
	}
	if !strings.Contains(dashboardTestSurface(), "requires admin role") {
		t.Fatal("dashboard should explain admin-only actions")
	}
}

func TestDashboardAPIErrorObservability(t *testing.T) {
	expected := []string{
		"apiStatusBanner",
		"apiStatusText",
		"Retry Last Request",
		"function rememberLastRequest",
		"function retryLastRequest",
		"function responseError",
		"function reportAPIError",
		"function clearAPIStatus",
		"function apiErrorHint",
		"function isBackgroundProtectedRead",
		"function isBackgroundProtectedPath",
		"function isAuthzError",
		"Check local API access and role permissions.",
		"Check daemon health, network access, and server logs.",
		"Control plane overview unavailable.",
		"Workflow alerts unavailable.",
		"Delivery health unavailable.",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing API error observability content %q", item)
		}
	}
}

func TestDashboardProtectedReadAuthzIsModuleScoped(t *testing.T) {
	expected := []string{
		"const suppressAuthError = opts.quietAuth || isBackgroundProtectedRead(url)",
		"if (!(suppressAuthError && isAuthzError(e)))",
		"pathname === '/api/v1/evaluation/ground-truth'",
		"pathname === '/api/v1/evaluation/correlation'",
		"Policy center requires local API access with policy permissions.",
		"Policy center is restricted by local API permissions.",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing module-scoped authz handling %q", item)
		}
	}
}

func TestDashboardActionableEmptyStates(t *testing.T) {
	expected := []string{
		"No agents reporting yet. Start an agent, confirm telemetry endpoint and API credentials",
		"No workflow alerts. Generate a test event, review active rules",
		"No delivery attempts yet. Configure notifiers or SIEM delivery",
		"Fleet action history unavailable. Check control-plane state storage and server logs.",
		"Delivery action history unavailable. Check delivery queue storage and server logs.",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing actionable empty-state content %q", item)
		}
	}
}

func TestDashboardPolicyValidationGuidance(t *testing.T) {
	expected := []string{
		"function validatePolicyMutationInput",
		"function policyErrorHint",
		"function policySuccessMessage",
		"function loadExamplePolicyRule",
		"Example Sigma rule loaded",
		"function renderPolicyDiffItem",
		"Rule ID is required before running",
		"Paste a Sigma rule with title and detection.condition",
		"Whitelist target and value are required",
		"Taint prefix is required",
		"Request approval in Compliance & SIEM",
		"Sigma validation passed; draft unchanged",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing policy validation guidance %q", item)
		}
	}
}

func TestDashboardWorkspaceNavigationRefactor(t *testing.T) {
	expected := []string{
		"workspace-nav",
		"data-dashboard-section=\"detect\"",
		"data-dashboard-section=\"investigate\"",
		"data-dashboard-section=\"respond\"",
		"data-dashboard-section=\"platform\"",
		"data-dashboard-section=\"govern\"",
		"switchDashboardSection",
		"dashboardPanelSection",
		"providaptDashboardSection",
		"setDashboardDensity",
		"providaptDashboardDensity",
		"resetDashboardLayout",
		"section-hidden",
		"defaultDashboardPanelOrder",
		"Module Quality Review",
		"module-quality-review",
		"Deployment Diagnostics",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing workspace navigation refactor content %q", item)
		}
	}
}

func TestDashboardStructuredIDSConsoleLayout(t *testing.T) {
	expected := []string{
		"dashboard-shell",
		"dashboard-sidebar",
		"Security operations navigation",
		"ProvidAPT SOC",
		"SOC Workflow",
		"Command Center",
		"Detect",
		"Investigate",
		"Respond",
		"Platform",
		"Module Quality",
		"soc-workflow-map",
		"showModuleQuality",
		"IDS Posture",
		"sidebarAgents",
		"sidebarOpenAlerts",
		"sidebarDeadLetters",
		"sidebarReadiness",
		"Severity Model",
		"dashboard-main",
		"updateSidebarPosture",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing structured IDS console content %q", item)
		}
	}
	panels := []string{
		"Module Quality Review",
		"Control Plane Summary",
		"Deployment Diagnostics",
		"Agent Overview",
		"Support Bundle",
		"Backup & Restore",
		"Policy Center",
		"Alert Workflow",
		"Evaluation Ground Truth",
		"Delivery Health",
		"Compliance & SIEM",
		"Investigation Console",
		"Operations Summary",
	}
	for _, panel := range panels {
		if !strings.Contains(dashboardTestSurface(), "<h2>"+panel+"</h2>") {
			t.Fatalf("dashboard missing panel %q", panel)
		}
	}
}

func TestDashboardGovernanceWorkbenchInteractions(t *testing.T) {
	expected := []string{
		"workflow-filter-bar",
		"workflowFilterStatus",
		"workflowFilterSeverity",
		"workflowFilterHost",
		"workflowFilterRule",
		"applyAlertWorkflowFilters",
		"resetAlertWorkflowFilters",
		"filteredAlertWorkflowAlerts",
		"Close Filtered Batch",
		"detail-drawer",
		"openDetailDrawer",
		"showAlertDetailsJSON",
		"showPolicyActionDetails",
		"openGraphFullscreen",
		"showAttackRouteMap",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing governance workbench interaction %q", item)
		}
	}
}

func TestDashboardUsabilityAndProfessionalViews(t *testing.T) {
	expected := []string{
		"data-table",
		"renderDataTable",
		"setDashboardTheme",
		"saveDashboardViewProfile",
		"loadDashboardViewProfile",
		"providaptDashboardViewProfile",
		"showEnvironmentOverview",
		"Environment View",
		"showMitreAttackMatrix",
		"MITRE Matrix",
		"showDetectionQualityDashboard",
		"Detection Quality",
		"buildExecutiveReport",
		"downloadExecutiveReport",
		"Executive Report",
		"dashboard-theme-contrast",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing usability or professional view %q", item)
		}
	}
}

func TestDashboardPanelResizeInteractions(t *testing.T) {
	expected := []string{
		"panel-resize-handle",
		"panel-size-badge",
		"providaptDashboardPanelSizes",
		"installPanelResize",
		"applyPanelSize",
		"savePanelSizes",
		"applyPanelSizes",
		"panel_sizes",
		"mousemove",
		"mouseup",
		"startHeight",
		"panel.getBoundingClientRect().height",
		"panel.style.height",
		"panel.style.maxHeight = 'none'",
		"body.style.height = 'auto'",
		"body.style.overflow = 'auto'",
		"panel-resize-active",
		"drag · resize",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing panel resize interaction %q", item)
		}
	}
}

func TestDashboardAdaptivePanelDoubleClickResize(t *testing.T) {
	expected := []string{
		"function adaptivePanelHeight",
		"function applyAdaptivePanelSize",
		"body.scrollHeight",
		"window.innerHeight - 96",
		"window.requestAnimationFrame",
		"applyAdaptivePanelSize(panel)",
		"function panelAdaptiveMinimumHeight",
		"panelAdaptiveMinimumHeight(panel)",
		"function panelAdaptiveMaximumHeight",
		"scrollReserve = body.querySelector",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing adaptive panel resize content %q", item)
		}
	}
	if strings.Contains(dashboardTestSurface(), "minHeight: 560") {
		t.Fatal("dashboard panel double-click resize should use adaptive content height, not fixed 560px")
	}
	if strings.Contains(dashboardTestSurface(), "Math.max(300") {
		t.Fatal("dashboard panel drag resize should use adaptive minimum height, not fixed 300px")
	}
}

func TestDashboardViewportOptimizationBreakpoints(t *testing.T) {
	for _, asset := range []string{`href="/assets/dashboard.css"`, `href="/assets/dashboard-responsive.css"`, `src="/assets/dashboard.js"`} {
		if !strings.Contains(dashboardHTMLDocument(), asset) {
			t.Fatalf("dashboard should link asset %s", asset)
		}
	}
	expected := []string{
		"@media (min-width: 1280px) and (max-width: 1439px)",
		"grid-template-columns: 218px minmax(0, 1fr)",
		"grid-auto-rows: 7px !important",
		"@media (min-width: 1800px) and (max-width: 2299px)",
		"max-width: 1960px",
		"repeat(2, minmax(620px, 1fr))",
		"@media (min-width: 2300px)",
		"max-width: 2560px",
		"repeat(3, minmax(480px, 1fr))",
		"grid-column: span 2",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardResponsiveCSS, item) {
			t.Fatalf("dashboard missing viewport optimization %q", item)
		}
	}
}

func TestDashboardResponsiveCSSAsset(t *testing.T) {
	ts := testServer(t)
	cases := []struct {
		path        string
		contentType string
		marker      string
	}{
		{"/assets/dashboard.css", "text/css", "--ids-bg-0"},
		{"/assets/dashboard-responsive.css", "text/css", "repeat(3, minmax(480px, 1fr))"},
		{"/assets/dashboard.js", "application/javascript", "function refresh()"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		ts.mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status = %d", tc.path, w.Code)
		}
		if !strings.Contains(w.Header().Get("Content-Type"), tc.contentType) {
			t.Fatalf("%s content type = %q", tc.path, w.Header().Get("Content-Type"))
		}
		if !strings.Contains(w.Body.String(), tc.marker) {
			t.Fatalf("%s missing marker %q", tc.path, tc.marker)
		}
	}
}

func TestDashboardForensicWorkbenchDesignLayer(t *testing.T) {
	expected := []string{
		"Forensic workbench design layer",
		"--forensic-bg: #080b0f",
		"--forensic-copper: #b9835a",
		"--forensic-cyan: #61d6e8",
		"--forensic-green: #77d99a",
		"--font-display",
		"--font-data",
		".content::before",
		"evidence spine",
		".dashboard-panel::before",
		".dashboard-panel h2::after",
		"width: 28px",
		":focus-visible",
		"prefers-reduced-motion",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardResponsiveCSS, item) {
			t.Fatalf("dashboard missing forensic workbench design layer %q", item)
		}
	}
}

func TestDashboardLeaderRetryForControlWrites(t *testing.T) {
	expected := []string{
		"postJSONWithLeaderRetry",
		"leaderRequestURL",
		"data.leader_endpoint",
		"retrying leader",
		"postJSON('/api/v1/control/support'",
		"postJSON('/api/v1/control/backup'",
		"/api/v1/control/upgrade",
		"postJSON('/api/v1/control/policies'",
		"postJSON('/api/v1/control/deliveries'",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard missing leader retry content %q", item)
		}
	}

	forbidden := []string{
		"fetch('/api/v1/control/support'",
		"fetch('/api/v1/control/backup'",
		"fetch('/api/v1/control/upgrade'",
		"fetch('/api/v1/control/policies'",
		"fetch('/api/v1/control/deliveries'",
	}
	for _, item := range forbidden {
		if strings.Contains(dashboardTestSurface(), item) {
			t.Fatalf("dashboard should use postJSON leader retry instead of direct fetch %q", item)
		}
	}
}
