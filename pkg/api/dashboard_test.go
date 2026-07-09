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
