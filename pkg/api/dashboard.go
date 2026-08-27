// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed templates/dashboard_shell.html
var dashboardShellHTML string

//go:embed templates/dashboard_metrics.html
var dashboardMetricsHTML string

//go:embed templates/dashboard_panels.html
var dashboardPanelsHTML string

//go:embed templates/panels/*.html
var dashboardPanelTemplates embed.FS

var dashboardHTML = renderDashboardHTML()

//go:embed static/dashboard.css
var dashboardCSS string

//go:embed static/dashboard-responsive.css
var dashboardResponsiveCSS string

//go:embed static/dashboard-api.js
var dashboardAPIJS string

//go:embed static/dashboard-state.js
var dashboardStateJS string

//go:embed static/dashboard-ui.js
var dashboardUIJS string

//go:embed static/dashboard-layout.js
var dashboardLayoutJS string

//go:embed static/dashboard-loaders.js
var dashboardLoadersJS string

//go:embed static/dashboard-fleet.js
var dashboardFleetJS string

//go:embed static/dashboard-policy.js
var dashboardPolicyJS string

//go:embed static/dashboard-workflow.js
var dashboardWorkflowJS string

//go:embed static/dashboard-ground-truth.js
var dashboardGroundTruthJS string

//go:embed static/dashboard-evidence.js
var dashboardEvidenceJS string

//go:embed static/dashboard.js
var dashboardJS string

//go:embed static/trace-viewer.css
var traceViewerCSS string

//go:embed static/trace-viewer.js
var traceViewerJS string

func renderDashboardHTML() string {
	html := strings.Replace(dashboardShellHTML, "{{DASHBOARD_METRICS}}", dashboardMetricsHTML, 1)
	html = strings.Replace(html, "{{DASHBOARD_PANELS}}", renderDashboardPanelsHTML(), 1)
	return html
}

func renderDashboardPanelsHTML() string {
	html := dashboardPanelsHTML
	for _, fileName := range dashboardPanelTemplateOrder {
		placeholder := "{{PANEL:" + fileName + "}}"
		panel := readDashboardPanelTemplate(fileName)
		html = strings.Replace(html, placeholder, strings.TrimRight(panel, "\n"), 1)
	}
	return html
}

func readDashboardPanelTemplate(fileName string) string {
	data, err := dashboardPanelTemplates.ReadFile("templates/panels/" + fileName)
	if err != nil {
		panic("dashboard panel template missing: " + fileName)
	}
	return string(data)
}

var dashboardPanelTemplateOrder = []string{
	"01_control_plane_summary.html",
	"02_deployment_diagnostics.html",
	"03_agent_overview.html",
	"04_support_bundle.html",
	"05_backup_restore.html",
	"06_policy_center.html",
	"07_alert_workflow.html",
	"08_evaluation_ground_truth.html",
	"09_delivery_health.html",
	"10_compliance_siem.html",
	"11_investigation_console.html",
	"12_operations_summary.html",
}

func (s *Server) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	_, _ = w.Write([]byte(dashboardHTML))
}

func (s *Server) handleDashboardCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardCSS))
}

func (s *Server) handleDashboardResponsiveCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardResponsiveCSS))
}

func (s *Server) handleDashboardAPIJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardAPIJS))
}

func (s *Server) handleDashboardStateJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardStateJS))
}

func (s *Server) handleDashboardUIJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardUIJS))
}

func (s *Server) handleDashboardLayoutJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardLayoutJS))
}

func (s *Server) handleDashboardLoadersJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardLoadersJS))
}

func (s *Server) handleDashboardFleetJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardFleetJS))
}

func (s *Server) handleDashboardPolicyJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardPolicyJS))
}

func (s *Server) handleDashboardWorkflowJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardWorkflowJS))
}

func (s *Server) handleDashboardGroundTruthJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardGroundTruthJS))
}

func (s *Server) handleDashboardEvidenceJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardEvidenceJS))
}

func (s *Server) handleDashboardJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardJS))
}

func (s *Server) handleTraceViewerCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(traceViewerCSS))
}

func (s *Server) handleTraceViewerJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(traceViewerJS))
}
