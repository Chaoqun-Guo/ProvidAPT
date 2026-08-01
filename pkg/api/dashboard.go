// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	_ "embed"
	"net/http"
)

//go:embed dashboard.html
var dashboardHTML string

//go:embed static/dashboard-responsive.css
var dashboardResponsiveCSS string

func (s *Server) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	_, _ = w.Write([]byte(dashboardHTML))
}

func (s *Server) handleDashboardResponsiveCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(dashboardResponsiveCSS))
}
