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
