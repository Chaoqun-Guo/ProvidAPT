package api

import (
	"strings"
	"testing"
)

func TestDashboardAlertWorkflowSeparators(t *testing.T) {
	if strings.Contains(dashboardHTML, " \u8def ") {
		t.Fatal("alert workflow dashboard should not render mojibake separators")
	}
	if !strings.Contains(dashboardHTML, " · ") {
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
		if !strings.Contains(dashboardHTML, item) {
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
		if !strings.Contains(dashboardHTML, item) {
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
		if strings.Contains(dashboardHTML, item) {
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
	}
	for _, item := range expected {
		if !strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard missing investigation console content %q", item)
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
		if strings.Contains(dashboardHTML, item) {
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
		"activationState",
		"topVersion",
		"openLicenseUpgradePage('activation')",
		"openLicenseUpgradePage('upgrade')",
		"License Activation",
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
		"runAlertWorkflowBulkAction('close')",
		"runAlertWorkflowBulkAction('silence')",
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
		"runApprovalAction",
		"runComplianceAction('test_siem')",
		"native connector",
		"readiness",
		"prepareUpgradeAction('apply')",
		"prepareUpgradeAction('rollback')",
		"/api/v1/control/compliance",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard missing module action %q", item)
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
		if !strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard missing semantic button class content %q", item)
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
		"/api/v1/evaluation/ground-truth?limit=500",
		"/api/v1/evaluation/correlation?limit=200",
		"parseGroundTruthJSONL",
		"renderGroundTruthRecord",
		"renderGroundTruthCorrelation",
		"filterGroundTruth('malicious')",
		"gtMalicious",
		"gtBenign",
		"groundTruthPhaseGrid",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard missing ground truth content %q", item)
		}
	}
}

func TestDashboardAdminActionsGiveFeedback(t *testing.T) {
	forbidden := []string{
		"if (currentRole !== 'admin') {\n    return;\n  }",
		"if (currentRole !== 'admin') return;",
	}
	for _, item := range forbidden {
		if strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard has silent admin guard %q", item)
		}
	}
	if !strings.Contains(dashboardHTML, "requires admin role") {
		t.Fatal("dashboard should explain admin-only actions")
	}
}

func TestDashboardAPIKeyAuthenticationUI(t *testing.T) {
	expected := []string{
		"apiKeyInput",
		"providapt_api_key",
		"testAPIKeyPermissions",
		"copyStatusCurl",
		"showRBACPermissions",
		"Authorization: Bearer",
		"function authHeaders",
		"'X-API-Key': apiKey",
		"downloadWithAuth('/api/v1/control/support/download'",
		"downloadWithAuth('/api/v1/control/backup/download'",
		"downloadWithAuth('/api/v1/control/policies/bundle'",
		"downloadAuditCSV",
		"format: 'csv'",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard missing API key auth content %q", item)
		}
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
		"Check the API key and role permissions.",
		"Check daemon health, network access, and server logs.",
		"Control plane overview unavailable.",
		"Workflow alerts unavailable.",
		"Delivery health unavailable.",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard missing API error observability content %q", item)
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
		if !strings.Contains(dashboardHTML, item) {
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
		if !strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard missing policy validation guidance %q", item)
		}
	}
}

func TestDashboardCommercialWorkflowEnhancements(t *testing.T) {
	expected := []string{
		"bulkFleetEnrollment('approved')",
		"bulkFleetEnrollment('quarantined')",
		"No agents match the current group/tag filter for bulk fleet action",
		"bulk precheck",
		"supportBundleRange",
		"supportBundleIncludes",
		"supportBundleRedaction",
		"compact-input-grid",
		"policy-editor compact",
		"Prepare cutover blocked: restore a backup to staging first",
		"function showDeliveryGroup",
		"showReleaseReadiness",
		"showAuditSearch",
		"siem test",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard missing commercial workflow enhancement %q", item)
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
		"postJSON('/api/v1/control/license'",
		"postJSON('/api/v1/control/upgrade'",
		"postJSON('/api/v1/control/policies'",
		"postJSON('/api/v1/control/deliveries'",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard missing leader retry content %q", item)
		}
	}

	forbidden := []string{
		"fetch('/api/v1/control/support'",
		"fetch('/api/v1/control/backup'",
		"fetch('/api/v1/control/license'",
		"fetch('/api/v1/control/upgrade'",
		"fetch('/api/v1/control/policies'",
		"fetch('/api/v1/control/deliveries'",
	}
	for _, item := range forbidden {
		if strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard should use postJSON leader retry instead of direct fetch %q", item)
		}
	}
}
