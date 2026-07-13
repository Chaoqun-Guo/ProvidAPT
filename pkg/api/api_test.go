// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

// ── Test helpers ────────────────────────────────────────────

func testGraph(t *testing.T) *provenance.Graph {
	t.Helper()
	g := provenance.NewGraph()
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessFork, TimestampNS: 1000,
		PID: 1, ChildPID: 100, Comm: "bash",
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileOpen, TimestampNS: 2000,
		PID: 100, Pathname: "/etc/shadow",
		Inode: 5000, DevMajor: 8, DevMinor: 3,
		Comm: "cat",
	})
	return g
}

func testServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(":0", testGraph(t), nil)
}

func apiGet(ts *Server, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

func apiServe(ts *Server, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	ts.Handler().ServeHTTP(w, req)
	return w
}

// ── Tests ───────────────────────────────────────────────────

func TestStatus(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/status")

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "running" {
		t.Errorf("status = %v", resp["status"])
	}
}

func TestHealthTelemetryFields(t *testing.T) {
	ts := testServer(t)
	ts.SetHealthFunc(func() HealthStatus {
		return HealthStatus{
			Status:               "healthy",
			UptimeSeconds:        42,
			EbpfCollector:        true,
			PipelineHealthy:      true,
			StoreHealthy:         true,
			EventsIngested:       7,
			MemoryBytes:          1024,
			Version:              "test",
			TelemetryEnabled:     true,
			TelemetryHealthy:     true,
			TelemetryLastSuccess: "2026-06-07T00:00:00Z",
		}
	})

	w := apiGet(ts, "/health")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["telemetry_enabled"] != true {
		t.Fatalf("telemetry_enabled = %v", resp["telemetry_enabled"])
	}
	if resp["telemetry_healthy"] != true {
		t.Fatalf("telemetry_healthy = %v", resp["telemetry_healthy"])
	}
	if resp["telemetry_last_success"] != "2026-06-07T00:00:00Z" {
		t.Fatalf("telemetry_last_success = %v", resp["telemetry_last_success"])
	}
}

func TestClusterOverviewEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetClusterOverviewFunc(func() ClusterOverview {
		return ClusterOverview{
			UpdatedAt:      "2026-06-08T00:00:00Z",
			TotalAgents:    2,
			HealthyAgents:  1,
			DegradedAgents: 1,
			Agents: []ClusterAgent{
				{AgentID: "agent-a", Status: "HEALTHY"},
				{AgentID: "agent-b", Status: "DEGRADED"},
			},
		}
	})

	w := apiGet(ts, "/api/v1/control/overview")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["total_agents"] != float64(2) {
		t.Fatalf("total_agents = %v", resp["total_agents"])
	}
	agents, ok := resp["agents"].([]interface{})
	if !ok || len(agents) != 2 {
		t.Fatalf("agents = %#v", resp["agents"])
	}
}

func TestTenantScopedClusterOverview(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"tenant-key"},
		map[string]string{"tenant-key": RoleAnalyst},
		map[string]string{"tenant-key": "Tenant Analyst"},
		true,
	)
	ts.SetAPIAuthTenants(map[string]string{"tenant-key": "prod"})
	ts.SetClusterOverviewFunc(func() ClusterOverview {
		return ClusterOverview{
			UpdatedAt: "2026-06-08T00:00:00Z",
			Agents: []ClusterAgent{
				{AgentID: "agent-prod", Group: "prod", Status: "HEALTHY"},
				{AgentID: "agent-dev", Group: "dev", Status: "DEGRADED"},
			},
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/overview", nil)
	req.Header.Set("X-API-Key", "tenant-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["tenant"] != "prod" || resp["total_agents"] != float64(1) {
		t.Fatalf("tenant overview = %#v", resp)
	}
}

func TestFleetEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetFleetListFunc(func(group, tag string) FleetList {
		return FleetList{
			UpdatedAt: "2026-06-08T00:00:00Z",
			Group:     group,
			Tag:       tag,
			Agents: []ClusterAgent{
				{AgentID: "agent-a", Group: "prod", Tags: []string{"linux", "db"}, Status: "HEALTHY"},
			},
			History: []ControlActionAudit{{
				Action:      "fleet_update",
				Actor:       "SecOps On-Call (admin)",
				Role:        RoleAdmin,
				TargetID:    "agent-a",
				Status:      "updated",
				Message:     "fleet metadata updated: group=prod tags=linux,db",
				PerformedAt: "2026-06-08T00:05:00Z",
			}},
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/fleet?group=prod&tag=linux", nil)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["group"] != "prod" {
		t.Fatalf("group = %v", resp["group"])
	}
	if resp["tag"] != "linux" {
		t.Fatalf("tag = %v", resp["tag"])
	}
	history, ok := resp["history"].([]interface{})
	if !ok || len(history) != 1 {
		t.Fatalf("history = %#v", resp["history"])
	}
}

func TestTenantScopedFleetAccess(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"tenant-key"},
		map[string]string{"tenant-key": RoleAnalyst},
		map[string]string{"tenant-key": "Tenant Analyst"},
		true,
	)
	ts.SetAPIAuthTenants(map[string]string{"tenant-key": "prod"})
	var gotGroup string
	ts.SetFleetListFunc(func(group, tag string) FleetList {
		gotGroup = group
		return FleetList{UpdatedAt: "2026-06-08T01:02:03Z", Group: group, Agents: []ClusterAgent{}}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/fleet", nil)
	req.Header.Set("X-API-Key", "tenant-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotGroup != "prod" {
		t.Fatalf("group = %q", gotGroup)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/control/fleet?group=dev", nil)
	req.Header.Set("X-API-Key", "tenant-key")
	w = apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross tenant status code = %d", w.Code)
	}
}

func TestFleetUpdateEndpoint(t *testing.T) {
	ts := testServer(t)
	var got FleetUpdate
	ts.SetFleetUpdateFunc(func(update FleetUpdate) error {
		got = update
		return nil
	})

	body := bytes.NewBufferString(`{"agent_id":"agent-a","action":"approved","group":"prod","tags":["linux","db"],"status":"approved"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/fleet", body)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if got.AgentID != "agent-a" || got.Action != "approved" || got.Group != "prod" || len(got.Tags) != 2 || got.Status != "approved" {
		t.Fatalf("update = %#v", got)
	}
}

func TestFleetUpdateInjectsActorAndRole(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"admin-key"},
		map[string]string{"admin-key": RoleAdmin},
		map[string]string{"admin-key": "SecOps On-Call"},
		true,
	)
	var got FleetUpdate
	ts.SetFleetUpdateFunc(func(update FleetUpdate) error {
		got = update
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/fleet", bytes.NewBufferString(`{"agent_id":"agent-a","group":"prod","tags":["linux"],"note":"owner confirmed"}`))
	req.Header.Set("X-API-Key", "admin-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if got.Role != RoleAdmin {
		t.Fatalf("role = %q", got.Role)
	}
	if got.Actor != "SecOps On-Call (admin)" {
		t.Fatalf("actor = %q", got.Actor)
	}
	if got.Note != "owner confirmed" {
		t.Fatalf("note = %q", got.Note)
	}
}

func TestRBACAnalystForbiddenFleetUpdate(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/fleet", bytes.NewBufferString(`{"agent_id":"a1"}`))
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestRBACAuditorGraphDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"auditor-key"}, map[string]string{"auditor-key": RoleAuditor}, nil, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/graph/export", nil)
	req.Header.Set("X-API-Key", "auditor-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestRBACAuditorStatusAllowed(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"auditor-key"}, map[string]string{"auditor-key": RoleAuditor}, nil, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("X-API-Key", "auditor-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["role"] != "auditor" {
		t.Fatalf("role = %v", resp["role"])
	}
}

func TestTrustedHeaderAuth(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"admin-key"}, map[string]string{"admin-key": RoleAdmin}, nil, true)
	ts.SetTrustedHeaderAuth(true, "X-SSO-User", "X-SSO-Role")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("X-SSO-User", "alice@example.com")
	req.Header.Set("X-SSO-Role", RoleAuditor)
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["role"] != RoleAuditor {
		t.Fatalf("role = %v", resp["role"])
	}
}

func TestSupportBundleEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetSupportBundleFunc(func() SupportBundleSummary {
		return SupportBundleSummary{
			LastBundlePath:  "/var/log/providapt/support-bundle-20260608T010203Z",
			LastArchivePath: "/var/log/providapt/support-bundle-20260608T010203Z.zip",
			LastReason:      "manual support bundle export | note: triage package",
			LastActor:       "SecOps On-Call (admin)",
			LastRole:        RoleAdmin,
			LastStatus:      "archived",
			LastBundleAt:    "2026-06-08T01:02:03Z",
			LastArchiveAt:   "2026-06-08T01:02:04Z",
			Redacted:        true,
			DownloadURL:     "/api/v1/control/support/download",
			History: []ControlActionAudit{{
				Action:      "support_bundle_export",
				Actor:       "SecOps On-Call (admin)",
				Role:        RoleAdmin,
				TargetID:    "/var/log/providapt/support-bundle-20260608T010203Z.zip",
				Status:      "archived",
				Message:     "support bundle exported and archived",
				Note:        "triage package",
				PerformedAt: "2026-06-08T01:02:03Z",
			}},
		}
	})

	w := apiGet(ts, "/api/v1/control/support")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["last_status"] != "archived" {
		t.Fatalf("last_status = %v", resp["last_status"])
	}
	if resp["redacted"] != true {
		t.Fatalf("redacted = %v", resp["redacted"])
	}
	history, ok := resp["history"].([]interface{})
	if !ok || len(history) != 1 {
		t.Fatalf("history = %#v", resp["history"])
	}
}

func TestSupportBundleActionInjectsActorAndRole(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"admin-key"},
		map[string]string{"admin-key": RoleAdmin},
		map[string]string{"admin-key": "SecOps On-Call"},
		true,
	)
	var gotReq SupportBundleActionRequest
	ts.SetSupportBundleActionFunc(func(req SupportBundleActionRequest) (SupportBundleActionResult, error) {
		gotReq = req
		return SupportBundleActionResult{
			Status:      "archived",
			BundlePath:  "/tmp/support-bundle-1",
			ArchivePath: "/tmp/support-bundle-1.zip",
			DownloadURL: "/api/v1/control/support/download",
			Redacted:    true,
			Reason:      req.Reason,
			PerformedAt: "2026-06-08T01:02:03Z",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/support", bytes.NewBufferString(`{"reason":"manual export","note":"triage package"}`))
	req.Header.Set("X-API-Key", "admin-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Role != RoleAdmin {
		t.Fatalf("role = %q", gotReq.Role)
	}
	if gotReq.Actor != "SecOps On-Call (admin)" {
		t.Fatalf("actor = %q", gotReq.Actor)
	}
	if gotReq.Note != "triage package" {
		t.Fatalf("note = %q", gotReq.Note)
	}
}

func TestRBACAnalystSupportBundleDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/support", bytes.NewBufferString(`{"reason":"manual export"}`))
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestSupportBundleDownloadEndpoint(t *testing.T) {
	ts := testServer(t)
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "support-bundle.zip")
	if err := os.WriteFile(archivePath, []byte("zip-bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	ts.SetSupportBundleDownloadFunc(func(actor, role string) (SupportBundleDownload, error) {
		return SupportBundleDownload{
			Path:     archivePath,
			FileName: "support-bundle.zip",
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/support/download", nil)
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "application/zip") {
		t.Fatalf("content-type = %q", got)
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "support-bundle.zip") {
		t.Fatalf("content-disposition = %q", got)
	}
	if body := w.Body.String(); body != "zip-bytes" {
		t.Fatalf("body = %q", body)
	}
}

func TestRBACAnalystSupportBundleDownloadDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/support/download", nil)
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestBackupEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetBackupFunc(func() BackupSummary {
		return BackupSummary{
			LastBackupPath: "/var/lib/providapt/backups/providapt-backup.tar.gz",
			LastAction:     "create",
			LastActor:      "SecOps On-Call (admin)",
			LastRole:       RoleAdmin,
			LastStatus:     "created",
			LastBackupAt:   "2026-06-08T01:02:03Z",
			SizeBytes:      1234,
			DownloadURL:    "/api/v1/control/backup/download",
			History: []ControlActionAudit{{
				Action:      "backup_create",
				Actor:       "SecOps On-Call (admin)",
				Role:        RoleAdmin,
				TargetID:    "/var/lib/providapt/backups/providapt-backup.tar.gz",
				Status:      "created",
				Message:     "checkpoint backup created",
				PerformedAt: "2026-06-08T01:02:03Z",
			}},
		}
	})

	w := apiGet(ts, "/api/v1/control/backup")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["last_status"] != "created" || resp["download_url"] != "/api/v1/control/backup/download" {
		t.Fatalf("backup summary = %#v", resp)
	}
}

func TestBackupActionInjectsActorAndRole(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"admin-key"},
		map[string]string{"admin-key": RoleAdmin},
		map[string]string{"admin-key": "SecOps On-Call"},
		true,
	)
	var gotReq BackupActionRequest
	ts.SetBackupActionFunc(func(req BackupActionRequest) (BackupActionResult, error) {
		gotReq = req
		return BackupActionResult{
			Status:      "created",
			Action:      req.Action,
			BackupPath:  "/tmp/providapt-backup.tar.gz",
			DownloadURL: "/api/v1/control/backup/download",
			PerformedAt: "2026-06-08T01:02:03Z",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/backup", bytes.NewBufferString(`{"action":"create","note":"pre-upgrade"}`))
	req.Header.Set("X-API-Key", "admin-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Role != RoleAdmin || gotReq.Actor != "SecOps On-Call (admin)" || gotReq.Note != "pre-upgrade" {
		t.Fatalf("request = %#v", gotReq)
	}
}

func TestBackupDownloadEndpoint(t *testing.T) {
	ts := testServer(t)
	dir := t.TempDir()
	backupPath := filepath.Join(dir, "providapt-backup.tar.gz")
	if err := os.WriteFile(backupPath, []byte("backup-bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	ts.SetBackupDownloadFunc(func(actor, role string) (BackupDownload, error) {
		return BackupDownload{Path: backupPath, FileName: "providapt-backup.tar.gz"}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/backup/download", nil)
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "providapt-backup.tar.gz") {
		t.Fatalf("content-disposition = %q", got)
	}
	if body := w.Body.String(); body != "backup-bytes" {
		t.Fatalf("body = %q", body)
	}
}

func TestRBACAnalystBackupDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/backup", bytes.NewBufferString(`{"action":"create"}`))
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestRBACAuditorBackupDownloadDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"auditor-key"}, map[string]string{"auditor-key": RoleAuditor}, nil, true)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/backup/download", nil)
	req.Header.Set("X-API-Key", "auditor-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestSecurityEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetSecurityStatusFunc(func() SecurityStatus {
		return SecurityStatus{
			UpdatedAt:      "2026-06-08T01:02:03Z",
			CertFile:       "/etc/providapt/server.crt",
			KeyFile:        "/etc/providapt/server.key",
			CAFile:         "/etc/providapt/ca.crt",
			RotationNeeded: true,
			LastStatus:     "checked",
			History: []ControlActionAudit{{
				Action:      "security_check_rotation",
				Status:      "checked",
				Message:     "certificate rotation checked",
				PerformedAt: "2026-06-08T01:02:03Z",
			}},
		}
	})

	w := apiGet(ts, "/api/v1/control/security")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["rotation_needed"] != true || resp["cert_file"] != "/etc/providapt/server.crt" {
		t.Fatalf("security status = %#v", resp)
	}
}

func TestSecurityActionInjectsActorAndRole(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"admin-key"},
		map[string]string{"admin-key": RoleAdmin},
		map[string]string{"admin-key": "SecOps On-Call"},
		true,
	)
	var gotReq SecurityActionRequest
	ts.SetSecurityActionFunc(func(req SecurityActionRequest) (SecurityActionResult, error) {
		gotReq = req
		return SecurityActionResult{
			Status:      "rotated",
			Action:      req.Action,
			CertFile:    "/etc/providapt/server.crt",
			PerformedAt: "2026-06-08T01:02:03Z",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/security", bytes.NewBufferString(`{"action":"rotate_server_cert","note":"quarterly"}`))
	req.Header.Set("X-API-Key", "admin-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Role != RoleAdmin || gotReq.Actor != "SecOps On-Call (admin)" || gotReq.Note != "quarterly" {
		t.Fatalf("request = %#v", gotReq)
	}
}

func TestRBACAnalystSecurityActionDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/security", bytes.NewBufferString(`{"action":"rotate_server_cert"}`))
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestAuditFeedEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetAuditQueryFunc(func(category, source string, limit int) AuditFeed {
		return AuditFeed{
			UpdatedAt: "2026-06-08T02:00:00Z",
			Category:  category,
			Source:    source,
			Entries: []AuditEntry{{
				ID:        "audit-1",
				Timestamp: "2026-06-08T01:59:00Z",
				Category:  "admin",
				Severity:  "INFO",
				Message:   "Support bundle archive downloaded",
				Source:    "supportbundle",
				Details: map[string]interface{}{
					"actor":        "SecOps On-Call (admin)",
					"archive_path": "/tmp/support-bundle-1.zip",
				},
			}},
		}
	})

	w := apiGet(ts, "/api/v1/control/audit?category=admin&source=supportbundle&limit=8")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["category"] != "admin" {
		t.Fatalf("category = %v", resp["category"])
	}
	entries, ok := resp["entries"].([]interface{})
	if !ok || len(entries) != 1 {
		t.Fatalf("entries = %#v", resp["entries"])
	}
}

func TestAuditFeedCSVExport(t *testing.T) {
	ts := testServer(t)
	ts.SetAuditQueryFunc(func(category, source string, limit int) AuditFeed {
		return AuditFeed{
			UpdatedAt: "2026-06-08T02:00:00Z",
			Category:  category,
			Source:    source,
			Entries: []AuditEntry{{
				ID:        "audit-1",
				Timestamp: "2026-06-08T01:59:00Z",
				Category:  "admin",
				Severity:  "INFO",
				Message:   "Policy bundle downloaded",
				Source:    "policy",
				Details: map[string]interface{}{
					"actor": "SecOps",
				},
			}},
		}
	})

	w := apiGet(ts, "/api/v1/control/audit?category=admin&source=policy&format=csv")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/csv") {
		t.Fatalf("content type = %q", got)
	}
	body := w.Body.String()
	if !strings.Contains(body, "id,timestamp,category,severity,source,message,details") || !strings.Contains(body, "audit-1") {
		t.Fatalf("csv body = %q", body)
	}
}

func TestTenantScopedAuditFeed(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"tenant-key"},
		map[string]string{"tenant-key": RoleAuditor},
		map[string]string{"tenant-key": "Tenant Auditor"},
		true,
	)
	ts.SetAPIAuthTenants(map[string]string{"tenant-key": "prod"})
	ts.SetAuditQueryFunc(func(category, source string, limit int) AuditFeed {
		return AuditFeed{
			UpdatedAt: "2026-06-08T02:00:00Z",
			Category:  category,
			Source:    source,
			Entries: []AuditEntry{
				{ID: "audit-prod", Category: "admin", Source: "policy", Details: map[string]interface{}{"tenant": "prod"}},
				{ID: "audit-dev", Category: "admin", Source: "policy", Details: map[string]interface{}{"tenant": "dev"}},
			},
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/audit?category=admin", nil)
	req.Header.Set("X-API-Key", "tenant-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	entries := resp["entries"].([]interface{})
	if resp["tenant"] != "prod" || len(entries) != 1 {
		t.Fatalf("tenant audit feed = %#v", resp)
	}
}

func TestRBACAuditorAuditFeedAllowed(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"auditor-key"}, map[string]string{"auditor-key": RoleAuditor}, nil, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/audit?category=admin&source=supportbundle", nil)
	req.Header.Set("X-API-Key", "auditor-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestLicenseEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetLicenseStatusFunc(func() LicenseStatus {
		return LicenseStatus{
			UpdatedAt:          "2026-06-08T03:00:00Z",
			Path:               "/etc/providapt/license.key",
			LicenseID:          "lic-enterprise-001",
			Present:            true,
			SizeBytes:          128,
			ModifiedAt:         "2026-06-08T02:59:00Z",
			Customer:           "Acme Corp",
			Edition:            "enterprise",
			ExpiresAt:          "2026-12-31T00:00:00Z",
			GracePeriodDays:    14,
			RevocationSource:   "remote:https://licenses.example.com/revocations.json",
			RevocationVerified: true,
			SignaturePresent:   true,
			SignatureVerified:  true,
			CurrentVersion:     "1.2.3",
			LastValidatedAt:    "2026-06-08T03:00:00Z",
			History: []ControlActionAudit{{
				Action:      "license_validate",
				Actor:       "SecOps On-Call (admin)",
				Role:        RoleAdmin,
				Status:      "validated",
				Message:     "license file validated",
				PerformedAt: "2026-06-08T03:00:00Z",
			}},
		}
	})

	w := apiGet(ts, "/api/v1/control/license")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["present"] != true {
		t.Fatalf("present = %v", resp["present"])
	}
	if resp["path"] != "/etc/providapt/license.key" {
		t.Fatalf("path = %v", resp["path"])
	}
	if resp["customer"] != "Acme Corp" {
		t.Fatalf("customer = %v", resp["customer"])
	}
	if resp["license_id"] != "lic-enterprise-001" {
		t.Fatalf("license_id = %v", resp["license_id"])
	}
}

func TestLicenseActionInjectsActorAndRole(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"admin-key"},
		map[string]string{"admin-key": RoleAdmin},
		map[string]string{"admin-key": "SecOps On-Call"},
		true,
	)
	var gotReq LicenseActionRequest
	ts.SetLicenseActionFunc(func(req LicenseActionRequest) (LicenseActionResult, error) {
		gotReq = req
		return LicenseActionResult{
			Status:            "validated",
			Message:           "license file validated",
			ValidatedAt:       "2026-06-08T03:00:00Z",
			ExpiresAt:         "2026-12-31T00:00:00Z",
			GracePeriodDays:   14,
			SignatureVerified: true,
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/license", bytes.NewBufferString(`{"action":"validate","note":"pre-maintenance check"}`))
	req.Header.Set("X-API-Key", "admin-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Role != RoleAdmin {
		t.Fatalf("role = %q", gotReq.Role)
	}
	if gotReq.Actor != "SecOps On-Call (admin)" {
		t.Fatalf("actor = %q", gotReq.Actor)
	}
	if gotReq.Note != "pre-maintenance check" {
		t.Fatalf("note = %q", gotReq.Note)
	}
}

func TestRBACAnalystLicenseActionDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/license", bytes.NewBufferString(`{"action":"validate"}`))
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestRBACAuditorLicenseAllowed(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"auditor-key"}, map[string]string{"auditor-key": RoleAuditor}, nil, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/license", nil)
	req.Header.Set("X-API-Key", "auditor-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestComplianceEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetComplianceStatusFunc(func() ComplianceStatus {
		return ComplianceStatus{
			UpdatedAt:       "2026-06-08T05:00:00Z",
			RetentionDays:   365,
			MaxAuditEntries: 25000,
			AuditEntries:    42,
			SIEM: SIEMStatus{
				Enabled:     true,
				Endpoint:    "file:///var/log/siem.ndjson",
				Format:      "json",
				MinSeverity: "WARNING",
				LastStatus:  "queued",
			},
			Approvals: ApprovalStatus{
				Enabled:         true,
				RequiredActions: []string{"policy.publish"},
				Pending: []ChangeApproval{{
					ID:          "appr-000001",
					Action:      "policy.publish",
					Status:      "pending",
					RequestedBy: "SecOps On-Call (admin)",
				}},
			},
		}
	})

	w := apiGet(ts, "/api/v1/control/compliance")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["retention_days"] != float64(365) {
		t.Fatalf("retention_days = %v", resp["retention_days"])
	}
	if resp["audit_entries"] != float64(42) {
		t.Fatalf("audit_entries = %v", resp["audit_entries"])
	}
}

func TestComplianceActionInjectsActorAndRole(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"admin-key"},
		map[string]string{"admin-key": RoleAdmin},
		map[string]string{"admin-key": "SecOps On-Call"},
		true,
	)
	var gotReq ComplianceActionRequest
	ts.SetComplianceActionFunc(func(req ComplianceActionRequest) (ComplianceActionResult, error) {
		gotReq = req
		return ComplianceActionResult{
			Status:      "completed",
			Message:     "compliance report generated",
			Path:        "/var/log/providapt/compliance/report.json",
			PerformedAt: "2026-06-08T05:00:00Z",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/compliance", bytes.NewBufferString(`{"action":"generate_report","note":"monthly review"}`))
	req.Header.Set("X-API-Key", "admin-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Role != RoleAdmin {
		t.Fatalf("role = %q", gotReq.Role)
	}
	if gotReq.Actor != "SecOps On-Call (admin)" {
		t.Fatalf("actor = %q", gotReq.Actor)
	}
	if gotReq.Note != "monthly review" {
		t.Fatalf("note = %q", gotReq.Note)
	}
}

func TestRBACComplianceActionDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/compliance", bytes.NewBufferString(`{"action":"generate_report"}`))
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestUpgradeEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetUpgradeReadinessFunc(func() UpgradeReadiness {
		return UpgradeReadiness{
			UpdatedAt:         "2026-06-08T04:00:00Z",
			CurrentVersion:    "1.2.3",
			GuidePath:         "docs/developer/testing.md",
			PackagePath:       "/tmp/providapt-upgrade.tar.gz",
			DownloadURL:       "https://downloads.example.com/providapt.tar.gz",
			PackagePresent:    true,
			ExpectedSHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PackageSHA256:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PackageVerified:   true,
			SignaturePath:     "/tmp/providapt-upgrade.tar.gz.sig",
			SignaturePresent:  true,
			SignatureVerified: true,
			RollbackPlan:      "snapshot VM before rollout",
			RollbackReady:     true,
			PreflightReady:    true,
			LastAction:        "check",
			LastActor:         "SecOps On-Call (admin)",
			LastActionAt:      "2026-06-08T04:00:00Z",
			LastNote:          "pre-maintenance check",
			History: []ControlActionAudit{{
				Action:      "upgrade_check",
				Actor:       "SecOps On-Call (admin)",
				Role:        RoleAdmin,
				Status:      "recorded",
				Message:     "upgrade readiness check recorded",
				PerformedAt: "2026-06-08T04:00:00Z",
			}},
		}
	})

	w := apiGet(ts, "/api/v1/control/upgrade")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["current_version"] != "1.2.3" {
		t.Fatalf("current_version = %v", resp["current_version"])
	}
	if resp["last_action"] != "check" {
		t.Fatalf("last_action = %v", resp["last_action"])
	}
	if resp["package_verified"] != true {
		t.Fatalf("package_verified = %v", resp["package_verified"])
	}
	if resp["signature_verified"] != true {
		t.Fatalf("signature_verified = %v", resp["signature_verified"])
	}
	if resp["preflight_ready"] != true {
		t.Fatalf("preflight_ready = %v", resp["preflight_ready"])
	}
}

func TestUpgradeActionInjectsActorAndRole(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"admin-key"},
		map[string]string{"admin-key": RoleAdmin},
		map[string]string{"admin-key": "SecOps On-Call"},
		true,
	)
	var gotReq UpgradeActionRequest
	ts.SetUpgradeActionFunc(func(req UpgradeActionRequest) (UpgradeActionResult, error) {
		gotReq = req
		return UpgradeActionResult{
			Status:            "recorded",
			Message:           "upgrade plan note recorded",
			PackagePath:       "/tmp/providapt-upgrade.tar.gz",
			DownloadURL:       "https://downloads.example.com/providapt.tar.gz",
			PackageSHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			PackageVerified:   false,
			SignaturePath:     "/tmp/providapt-upgrade.tar.gz.sig",
			SignatureVerified: false,
			PreflightReady:    false,
			PerformedAt:       "2026-06-08T04:00:00Z",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/upgrade", bytes.NewBufferString(`{"action":"record","note":"schedule during Sunday window","package_path":"/tmp/providapt-upgrade.tar.gz","download_url":"https://downloads.example.com/providapt.tar.gz","expected_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","signature_path":"/tmp/providapt-upgrade.tar.gz.sig","rollback_plan":"snapshot VM before rollout"}`))
	req.Header.Set("X-API-Key", "admin-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Role != RoleAdmin {
		t.Fatalf("role = %q", gotReq.Role)
	}
	if gotReq.Actor != "SecOps On-Call (admin)" {
		t.Fatalf("actor = %q", gotReq.Actor)
	}
	if gotReq.Note != "schedule during Sunday window" {
		t.Fatalf("note = %q", gotReq.Note)
	}
	if gotReq.PackagePath != "/tmp/providapt-upgrade.tar.gz" {
		t.Fatalf("package_path = %q", gotReq.PackagePath)
	}
	if gotReq.DownloadURL != "https://downloads.example.com/providapt.tar.gz" {
		t.Fatalf("download_url = %q", gotReq.DownloadURL)
	}
	if gotReq.SignaturePath != "/tmp/providapt-upgrade.tar.gz.sig" {
		t.Fatalf("signature_path = %q", gotReq.SignaturePath)
	}
}

func TestRBACAnalystUpgradeActionDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/upgrade", bytes.NewBufferString(`{"action":"check"}`))
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestRBACAuditorUpgradeAllowed(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"auditor-key"}, map[string]string{"auditor-key": RoleAuditor}, nil, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/upgrade", nil)
	req.Header.Set("X-API-Key", "auditor-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestPoliciesEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetPolicyCenterFunc(func() PolicyCenter {
		return PolicyCenter{
			UpdatedAt: "2026-06-08T00:00:00Z",
			Current: PolicySummary{
				Version:     2,
				State:       "published",
				ActiveRules: 5,
			},
			Draft: PolicySummary{
				Version:     2,
				State:       "draft",
				ActiveRules: 6,
			},
			History: []PolicySummary{{Version: 1, State: "published"}, {Version: 2, State: "published"}},
			Actions: []ControlActionAudit{{
				Action:      "publish",
				Actor:       "SecOps On-Call (admin)",
				Role:        RoleAdmin,
				Status:      "published",
				Message:     "policy published",
				PerformedAt: "2026-06-08T00:10:00Z",
			}},
		}
	})

	w := apiGet(ts, "/api/v1/control/policies")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	current, ok := resp["current"].(map[string]interface{})
	if !ok || current["version"] != float64(2) {
		t.Fatalf("current = %#v", resp["current"])
	}
	actions, ok := resp["actions"].([]interface{})
	if !ok || len(actions) != 1 {
		t.Fatalf("actions = %#v", resp["actions"])
	}
}

func TestPolicyActionEndpoint(t *testing.T) {
	ts := testServer(t)
	var gotReq PolicyActionRequest
	ts.SetPolicyActionFunc(func(req PolicyActionRequest) (PolicySummary, error) {
		gotReq = req
		return PolicySummary{
			Version:     3,
			State:       req.Action,
			ActiveRules: 7,
		}, nil
	})

	body := bytes.NewBufferString(`{"action":"publish","notes":"ship it","target_group":"prod","target_tag":"linux"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/policies", body)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["version"] != float64(3) {
		t.Fatalf("version = %v", resp["version"])
	}
	if gotReq.Action != "publish" {
		t.Fatalf("request = %#v", gotReq)
	}
	if gotReq.TargetGroup != "prod" || gotReq.TargetTag != "linux" {
		t.Fatalf("target filter = %#v", gotReq)
	}
}

func TestPolicyEditActionFields(t *testing.T) {
	ts := testServer(t)
	var gotReq PolicyActionRequest
	ts.SetPolicyActionFunc(func(req PolicyActionRequest) (PolicySummary, error) {
		gotReq = req
		return PolicySummary{Version: 3, State: "draft", ActiveRules: 8}, nil
	})

	body := bytes.NewBufferString(`{"action":"update_sigma","notes":"tighten detection","rule_id":"suspicious-shell","rule_yaml":"title: suspicious shell\nlogsource:\n  product: linux","whitelist_target":"comm","whitelist_value":"backup","taint_prefix":"10.0.0.0/8","taint_label":"external"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/policies", body)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Action != "update_sigma" || gotReq.RuleID != "suspicious-shell" {
		t.Fatalf("request = %#v", gotReq)
	}
	if gotReq.RuleYAML == "" || gotReq.WhitelistTarget != "comm" || gotReq.TaintPrefix != "10.0.0.0/8" {
		t.Fatalf("request fields = %#v", gotReq)
	}
}

func TestPolicyBundleDownloadEndpoint(t *testing.T) {
	ts := testServer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "policy-v3.json")
	if err := os.WriteFile(path, []byte(`{"version":3}`), 0600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	var gotVersion int
	ts.SetPolicyBundleDownloadFunc(func(version int, actor, role string) (PolicyBundleDownload, error) {
		gotVersion = version
		return PolicyBundleDownload{
			Path:     path,
			FileName: "providapt-policy-v3.json",
			SHA256:   "abc123",
			Version:  3,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/policies/bundle?version=3", nil)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotVersion != 3 {
		t.Fatalf("version = %d", gotVersion)
	}
	if w.Header().Get("X-Policy-Bundle-SHA256") != "abc123" {
		t.Fatalf("sha header = %q", w.Header().Get("X-Policy-Bundle-SHA256"))
	}
	if strings.TrimSpace(w.Body.String()) != `{"version":3}` {
		t.Fatalf("body = %q", w.Body.String())
	}
}

func TestRBACAnalystPolicyBundleDownloadDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/policies/bundle", nil)
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestPolicyActionInjectsActorAndRole(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"admin-key"},
		map[string]string{"admin-key": RoleAdmin},
		map[string]string{"admin-key": "SecOps On-Call"},
		true,
	)
	var gotReq PolicyActionRequest
	ts.SetPolicyActionFunc(func(req PolicyActionRequest) (PolicySummary, error) {
		gotReq = req
		return PolicySummary{Version: 3, State: "publish", ActiveRules: 7}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/policies", bytes.NewBufferString(`{"action":"publish","notes":"ship it"}`))
	req.Header.Set("X-API-Key", "admin-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Role != RoleAdmin {
		t.Fatalf("role = %q", gotReq.Role)
	}
	if gotReq.Actor != "SecOps On-Call (admin)" {
		t.Fatalf("actor = %q", gotReq.Actor)
	}
}

func TestRBACAnalystPolicyActionDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/policies", bytes.NewBufferString(`{"action":"publish"}`))
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestAlertWorkflowEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetAlertWorkflowFunc(func(status, assignee string) AlertWorkflow {
		return AlertWorkflow{
			UpdatedAt: "2026-06-08T00:00:00Z",
			Summary: AlertWorkflowSummary{
				Total: 3,
				Open:  1,
			},
			Alerts: []AlertWorkflowItem{{
				ID:       "a-1",
				Pattern:  "SIGMA_SHADOW",
				Headline: "shadow access",
				Status:   "open",
				Count:    2,
			}},
			History: []ControlActionAudit{{
				Action:      "assign",
				Actor:       "alice (analyst)",
				Role:        RoleAnalyst,
				TargetID:    "a-1",
				Status:      "assigned",
				Message:     "alert assigned to alice",
				PerformedAt: "2026-06-08T00:15:00Z",
			}},
		}
	})

	w := apiGet(ts, "/api/v1/control/alerts")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	summary := resp["summary"].(map[string]interface{})
	if summary["total"] != float64(3) {
		t.Fatalf("summary.total = %v", summary["total"])
	}
	history, ok := resp["history"].([]interface{})
	if !ok || len(history) != 1 {
		t.Fatalf("history = %#v", resp["history"])
	}
}

func TestAlertWorkflowActionEndpoint(t *testing.T) {
	ts := testServer(t)
	var gotReq AlertWorkflowActionRequest
	ts.SetAlertWorkflowActionFunc(func(req AlertWorkflowActionRequest) (AlertWorkflowItem, error) {
		gotReq = req
		return AlertWorkflowItem{
			ID:       req.AlertID,
			Status:   "assigned",
			Assignee: req.Assignee,
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/alerts", bytes.NewBufferString(`{"action":"assign","alert_id":"a-1","assignee":"alice"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["assignee"] != "alice" {
		t.Fatalf("assignee = %v", resp["assignee"])
	}
	if gotReq.Action != "assign" || gotReq.AlertID != "a-1" {
		t.Fatalf("request = %#v", gotReq)
	}
}

func TestAlertWorkflowActionInjectsActorAndRole(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"analyst-key"},
		map[string]string{"analyst-key": RoleAnalyst},
		map[string]string{"analyst-key": "SOC Analyst 1"},
		true,
	)
	var gotReq AlertWorkflowActionRequest
	ts.SetAlertWorkflowActionFunc(func(req AlertWorkflowActionRequest) (AlertWorkflowItem, error) {
		gotReq = req
		return AlertWorkflowItem{ID: req.AlertID, Status: "assigned", Assignee: req.Assignee}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/alerts", bytes.NewBufferString(`{"action":"assign","alert_id":"a-1","assignee":"alice","note":"triage"}`))
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Role != RoleAnalyst {
		t.Fatalf("role = %q", gotReq.Role)
	}
	if gotReq.Actor != "SOC Analyst 1 (analyst)" {
		t.Fatalf("actor = %q", gotReq.Actor)
	}
}

func TestRBACAuditorAlertWorkflowReadOnly(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"auditor-key"}, map[string]string{"auditor-key": RoleAuditor}, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/alerts", bytes.NewBufferString(`{"action":"assign","alert_id":"a-1"}`))
	req.Header.Set("X-API-Key", "auditor-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestNotifyDeliveriesEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetNotifyDeliveryFunc(func() NotifyDeliveryCenter {
		return NotifyDeliveryCenter{
			UpdatedAt: "2026-06-08T00:00:00Z",
			Summary: NotifyDeliverySummary{
				Delivered:  2,
				Retrying:   1,
				DeadLetter: 1,
			},
			Recent: []NotifyDeliveryRecord{{
				ID:          "delivery-1",
				Notifier:    "slack",
				AlertID:     "alert-1",
				Pattern:     "SIGMA_SHADOW",
				Severity:    "HIGH",
				Status:      "delivered",
				Attempt:     2,
				MaxAttempts: 3,
			}},
			DeadLetters: []NotifyDeliveryRecord{{
				ID:          "delivery-2",
				Notifier:    "webhook",
				AlertID:     "alert-2",
				Pattern:     "SIGMA_EXFIL",
				Severity:    "CRITICAL",
				Status:      "dead_letter",
				Attempt:     3,
				MaxAttempts: 3,
				Error:       "boom",
				TicketKey:   "SEC-7",
				TicketURL:   "https://jira.local/browse/SEC-7",
				TicketType:  "jira",
			}},
			History: []NotifyDeliveryAudit{{
				Action:      "create_ticket_all",
				Status:      "ticket_batch_partial",
				Message:     "processed 2 dead letter(s): 1 ticket(s) created, 1 skipped, 0 failed",
				Processed:   2,
				Succeeded:   1,
				Skipped:     1,
				PerformedAt: "2026-06-08T01:00:00Z",
			}},
		}
	})

	w := apiGet(ts, "/api/v1/control/deliveries")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	summary := resp["summary"].(map[string]interface{})
	if summary["dead_letter"] != float64(1) {
		t.Fatalf("summary.dead_letter = %v", summary["dead_letter"])
	}
	recent := resp["recent"].([]interface{})
	if len(recent) != 1 {
		t.Fatalf("recent = %#v", resp["recent"])
	}
	deadLetters := resp["dead_letters"].([]interface{})
	if len(deadLetters) != 1 {
		t.Fatalf("dead_letters = %#v", resp["dead_letters"])
	}
	history := resp["history"].([]interface{})
	if len(history) != 1 {
		t.Fatalf("history = %#v", resp["history"])
	}
}

func TestRBACAuditorNotifyDeliveriesAllowed(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"auditor-key"}, map[string]string{"auditor-key": RoleAuditor}, nil, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/deliveries", nil)
	req.Header.Set("X-API-Key", "auditor-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestNotifyDeliveryActionEndpoint(t *testing.T) {
	ts := testServer(t)
	var gotReq NotifyDeliveryActionRequest
	ts.SetNotifyDeliveryActionFunc(func(req NotifyDeliveryActionRequest) (NotifyDeliveryActionResult, error) {
		gotReq = req
		record := NotifyDeliveryRecord{ID: req.DeliveryID, Status: "delivered", Attempt: 1, MaxAttempts: 1}
		return NotifyDeliveryActionResult{
			Status:      "replayed",
			Message:     "ok",
			Record:      &record,
			PerformedAt: "2026-06-08T00:00:00Z",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/deliveries", bytes.NewBufferString(`{"action":"replay","delivery_id":"dlq-1"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "replayed" {
		t.Fatalf("status = %v", resp["status"])
	}
	if gotReq.Action != "replay" || gotReq.DeliveryID != "dlq-1" {
		t.Fatalf("request = %#v", gotReq)
	}
}

func TestNotifyDeliveryActionInjectsActorAndRole(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"admin-key"},
		map[string]string{"admin-key": RoleAdmin},
		map[string]string{"admin-key": "SecOps On-Call"},
		true,
	)
	var gotReq NotifyDeliveryActionRequest
	ts.SetNotifyDeliveryActionFunc(func(req NotifyDeliveryActionRequest) (NotifyDeliveryActionResult, error) {
		gotReq = req
		return NotifyDeliveryActionResult{
			Status:      "replayed",
			PerformedAt: "2026-06-08T00:00:00Z",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/deliveries", bytes.NewBufferString(`{"action":"replay","delivery_id":"dlq-1","note":"manual retry"}`))
	req.Header.Set("X-API-Key", "admin-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Role != RoleAdmin {
		t.Fatalf("role = %q", gotReq.Role)
	}
	if gotReq.Actor != "SecOps On-Call (admin)" {
		t.Fatalf("actor = %q", gotReq.Actor)
	}
	if gotReq.Note != "manual retry" {
		t.Fatalf("note = %q", gotReq.Note)
	}
}

func TestNotifyDeliveryActionHeaderActorOverridesIdentity(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"admin-key"},
		map[string]string{"admin-key": RoleAdmin},
		map[string]string{"admin-key": "SecOps On-Call"},
		true,
	)
	var gotReq NotifyDeliveryActionRequest
	ts.SetNotifyDeliveryActionFunc(func(req NotifyDeliveryActionRequest) (NotifyDeliveryActionResult, error) {
		gotReq = req
		return NotifyDeliveryActionResult{
			Status:      "replayed",
			PerformedAt: "2026-06-08T00:00:00Z",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/deliveries", bytes.NewBufferString(`{"action":"replay","delivery_id":"dlq-1"}`))
	req.Header.Set("X-API-Key", "admin-key")
	req.Header.Set("X-ProvidAPT-Actor", "alice")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if gotReq.Actor != "alice (admin)" {
		t.Fatalf("actor = %q", gotReq.Actor)
	}
}

func TestNotifyDeliveryReplayAllEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetNotifyDeliveryActionFunc(func(req NotifyDeliveryActionRequest) (NotifyDeliveryActionResult, error) {
		return NotifyDeliveryActionResult{
			Status:      "replayed_batch",
			Processed:   2,
			Succeeded:   2,
			Failed:      0,
			Records:     []NotifyDeliveryRecord{{ID: "dlq-1"}, {ID: "dlq-2"}},
			PerformedAt: "2026-06-08T00:00:00Z",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/deliveries", bytes.NewBufferString(`{"action":"replay_all"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["processed"] != float64(2) {
		t.Fatalf("processed = %v", resp["processed"])
	}
}

func TestNotifyDeliveryCreateTicketAllEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetNotifyDeliveryActionFunc(func(req NotifyDeliveryActionRequest) (NotifyDeliveryActionResult, error) {
		return NotifyDeliveryActionResult{
			Status:      "ticket_batch_partial",
			Processed:   3,
			Succeeded:   2,
			Skipped:     1,
			Failed:      0,
			Records:     []NotifyDeliveryRecord{{ID: "dlq-1", TicketKey: "SEC-1"}, {ID: "dlq-2", TicketKey: "INC001"}},
			PerformedAt: "2026-06-08T00:00:00Z",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/deliveries", bytes.NewBufferString(`{"action":"create_ticket_all"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["skipped"] != float64(1) {
		t.Fatalf("skipped = %v", resp["skipped"])
	}
	if resp["succeeded"] != float64(2) {
		t.Fatalf("succeeded = %v", resp["succeeded"])
	}
}

func TestRBACAnalystDeliveryActionDenied(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/deliveries", bytes.NewBufferString(`{"action":"replay","delivery_id":"dlq-1"}`))
	req.Header.Set("X-API-Key", "analyst-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestExport(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/graph/export")

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d", w.Code)
	}

	var resp cytoGraph
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.NodeCount < 2 {
		t.Errorf("nodes = %d, want ≥2", resp.Data.NodeCount)
	}
	if resp.Data.EdgeCount < 1 {
		t.Errorf("edges = %d, want ≥1", resp.Data.EdgeCount)
	}

	// Verify Cytoscape format
	if len(resp.Elements) == 0 {
		t.Fatal("no elements")
	}
	hasNode := false
	hasEdge := false
	for _, el := range resp.Elements {
		if el.Group == "nodes" {
			hasNode = true
			if el.Data.ID == "" {
				t.Error("node missing id")
			}
		}
		if el.Group == "edges" {
			hasEdge = true
			if el.Data.Source == "" || el.Data.Target == "" {
				t.Error("edge missing source/target")
			}
		}
	}
	if !hasNode {
		t.Error("no node elements")
	}
	if !hasEdge {
		t.Error("no edge elements")
	}
}

func TestExportFilterPID(t *testing.T) {
	ts := testServer(t)

	// Filter by PID 100
	w := apiGet(ts, "/api/v1/graph/export?pid=100")
	var resp cytoGraph
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Data.NodeCount == 0 {
		t.Error("expected nodes for PID 100")
	}
	t.Logf("PID=100 export: %d nodes, %d edges", resp.Data.NodeCount, resp.Data.EdgeCount)
}

func TestExportFilterPIDInvalid(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/graph/export?pid=99999")

	var resp cytoGraph
	json.NewDecoder(w.Body).Decode(&resp)
	t.Logf("invalid PID: %d nodes, %d edges", resp.Data.NodeCount, resp.Data.EdgeCount)
}

func TestBackwardTrace(t *testing.T) {
	ts := testServer(t)

	// Trace backward from the process that read shadow
	w := apiGet(ts, "/api/v1/graph/node/p:100/backward")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d: %s", w.Code, w.Body.String())
	}

	var resp cytoGraph
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data.NodeCount == 0 {
		t.Error("expected nodes in backward trace")
	}
	t.Logf("backward trace from p:100: %d nodes, %d edges",
		resp.Data.NodeCount, resp.Data.EdgeCount)
}

func TestForwardTrace(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/graph/node/p:1/forward")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}

	var resp cytoGraph
	json.NewDecoder(w.Body).Decode(&resp)
	t.Logf("forward trace from p:1: %d nodes, %d edges",
		resp.Data.NodeCount, resp.Data.EdgeCount)
}

func TestBackwardDepthParam(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/graph/node/p:100/backward?depth=2")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestNodeInvalidAction(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/graph/node/p:100/invalid")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected error for invalid action, got %d", w.Code)
	}
}

func TestAlertsEndpoint(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/alerts")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	t.Logf("alerts response: %v", resp)
}

func TestAlertSVGSubroute(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/alerts/p%3A100/svg")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "image/svg+xml" {
		t.Fatalf("content-type = %q", got)
	}
	if !strings.Contains(w.Body.String(), "<svg") {
		t.Fatal("expected SVG response body")
	}
}

func TestEventSearchMissingOutputDirReturnsEmptyResults(t *testing.T) {
	t.Setenv("PROVIDAPT_OUTPUT_DIR", filepath.Join(t.TempDir(), "missing"))
	ts := testServer(t)
	for _, path := range []string{"/api/v1/events/search?pattern=dropped&limit=50", "/api/v1/events/recent?limit=50"} {
		w := apiGet(ts, path)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status = %d body = %s", path, w.Code, w.Body.String())
		}
		var resp SearchResult
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if resp.Total != 0 || len(resp.Results) != 0 {
			t.Fatalf("%s got total=%d results=%d, want empty", path, resp.Total, len(resp.Results))
		}
	}
}

func TestCORSHeaders(t *testing.T) {
	ts := testServer(t)
	handler := corsMiddleware([]string{"*"})(ts.mux)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/status", nil)
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS header")
	}
}

func TestNotFound(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCytoFormat(t *testing.T) {
	// Direct test of Cytoscape format
	nodes := []*provenance.Node{
		{ID: "p:1", Label: "init", Subtype: "process"},
		{ID: "f:100", Label: "/etc/hosts", Subtype: "file"},
	}
	edges := []*provenance.Edge{
		{ID: "e1", Source: "p:1", Target: "f:100"},
	}

	w := httptest.NewRecorder()
	writeCytoscape(w, nodes, edges)

	var resp cytoGraph
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Elements) != 3 { // 2 nodes + 1 edge
		t.Errorf("elements = %d, want 3", len(resp.Elements))
	}
}

// ── SVG tests ──────────────────────────────────────────────

func TestSVGGeneration(t *testing.T) {
	g := testGraph(t)
	svg := generateAlertSVG("test-1", g)
	if len(svg) == 0 {
		t.Error("empty SVG")
	}
	if !strings.Contains(string(svg), "<svg") {
		t.Error("SVG missing <svg> tag")
	}
	if !strings.Contains(string(svg), "node-") {
		t.Error("SVG missing node classes")
	}
	t.Logf("SVG size: %d bytes", len(svg))
}

func TestSVGEmptyGraph(t *testing.T) {
	g := provenance.NewGraph()
	svg := generateAlertSVG("empty", g)
	if len(svg) == 0 {
		t.Error("empty SVG for empty graph")
	}
}

func TestSVGContentType(t *testing.T) {
	g := testGraph(t)
	svg := generateAlertSVG("test", g)
	if !strings.HasPrefix(string(svg), "<svg") {
		t.Error("SVG should start with <svg")
	}
}

// ── Helpers tests ──────────────────────────────────────────

func TestShortRel(t *testing.T) {
	tests := []struct{ in, want string }{
		{"prov:used", "used"},
		{"prov:wasGeneratedBy", "created"},
		{"prov:wasInformedBy", "forked"},
		{"prov:wasDerivedFrom", "derived"},
		{"custom", "custom"},
	}
	for _, tt := range tests {
		got := shortRel(tt.in)
		if got != tt.want {
			t.Errorf("shortRel(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if s := truncate("hello world", 5); s != "he..." {
		t.Errorf("truncate = %q", s)
	}
	if s := truncate("hello", 10); s != "hello" {
		t.Errorf("truncate short = %q", s)
	}
}

func TestQueryInt(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?depth=5", nil)
	if v := queryInt(r, "depth", 3); v != 5 {
		t.Errorf("queryInt = %d", v)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	if v := queryInt(r2, "depth", 3); v != 3 {
		t.Errorf("queryInt default = %d", v)
	}
}

func TestEscapeXML(t *testing.T) {
	if s := escapeXML("<hello & world>"); s != "&lt;hello &amp; world&gt;" {
		t.Errorf("escape = %q", s)
	}
}
