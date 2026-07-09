package api

import (
	"strings"
	"testing"
)

func TestDashboardAlertWorkflowSeparators(t *testing.T) {
	if strings.Contains(dashboardHTML, " 路 ") {
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
		"showFleetStatus('healthy')",
		"showFleetStatus('degraded')",
		"showAgentDetails",
		"applyFleetInputs",
		"markAgentReviewed",
		"showSupportDetails('history')",
		"showLicenseUpgradeDetails('package')",
		"showPolicyDetails('history')",
		"loadAlertWorkflowFiltered('open')",
		"runAlertWorkflowAction('assign'",
		"runAlertWorkflowAction('silence'",
		"runAlertWorkflowAction('close'",
		"showDeliveriesByStatus('dead_letter')",
		"alertTraceActions(a)",
	}
	for _, item := range expected {
		if !strings.Contains(dashboardHTML, item) {
			t.Fatalf("dashboard missing module action %q", item)
		}
	}
}
