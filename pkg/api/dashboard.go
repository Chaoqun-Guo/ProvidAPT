// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	_ "embed"
	"net/http"
)

//go:embed dashboard.html
var dashboardHTML string

//go:embed static/dashboard.css
var dashboardCSS string

//go:embed static/dashboard-responsive.css
var dashboardResponsiveCSS string

//go:embed static/dashboard-api.js
var dashboardAPIJS string

//go:embed static/dashboard.js
var dashboardJS string

//go:embed static/trace-viewer.css
var traceViewerCSS string

//go:embed static/trace-viewer.js
var traceViewerJS string

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
