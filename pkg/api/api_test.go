// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
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
		Comm: "cat", ExePath: "/usr/bin/cat", Cmdline: "cat /etc/shadow",
		PPID: 1, UID: 0, GID: 0,
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

func TestMultiTenantScopedFleetAccess(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"tenant-key"},
		map[string]string{"tenant-key": RoleOperator},
		map[string]string{"tenant-key": "Managed Operator"},
		true,
	)
	ts.SetAPIAuthTenants(map[string]string{"tenant-key": "prod,staging"})
	ts.SetFleetListFunc(func(group, tag string) FleetList {
		return FleetList{
			UpdatedAt: "2026-06-08T01:02:03Z",
			Group:     group,
			Tag:       tag,
			Agents: []ClusterAgent{
				{AgentID: "agent-prod", Group: "prod", Status: "HEALTHY"},
				{AgentID: "agent-staging", Group: "staging", Status: "HEALTHY"},
				{AgentID: "agent-dev", Group: "dev", Status: "DEGRADED"},
			},
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/fleet", nil)
	req.Header.Set("X-API-Key", "tenant-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d: %s", w.Code, w.Body.String())
	}
	var resp FleetList
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Agents) != 2 {
		t.Fatalf("agents = %#v", resp.Agents)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/control/fleet?group=dev", nil)
	req.Header.Set("X-API-Key", "tenant-key")
	w = apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross tenant status code = %d", w.Code)
	}
}

func TestOperatorCanUpdateScopedFleetOnly(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth(
		[]string{"operator-key"},
		map[string]string{"operator-key": RoleOperator},
		map[string]string{"operator-key": "Managed Operator"},
		true,
	)
	ts.SetAPIAuthTenants(map[string]string{"operator-key": "prod"})
	var got FleetUpdate
	ts.SetFleetUpdateFunc(func(update FleetUpdate) error {
		got = update
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/fleet", bytes.NewBufferString(`{"agent_id":"agent-a","action":"approved"}`))
	req.Header.Set("X-API-Key", "operator-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("scoped update status = %d: %s", w.Code, w.Body.String())
	}
	if got.Group != "prod" || got.Role != RoleOperator {
		t.Fatalf("update scope = %#v", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/control/fleet", bytes.NewBufferString(`{"agent_id":"agent-a","group":"dev"}`))
	req.Header.Set("X-API-Key", "operator-key")
	w = apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant update status = %d", w.Code)
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

func TestFleetBatchUpdateEndpoint(t *testing.T) {
	ts := testServer(t)
	var got []string
	ts.SetFleetUpdateFunc(func(update FleetUpdate) error {
		got = append(got, update.AgentID)
		return nil
	})

	body := bytes.NewBufferString(`{"agent_ids":["agent-a","agent-b","agent-a"],"action":"quarantined","note":"batch incident"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/fleet", body)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d: %s", w.Code, w.Body.String())
	}
	if len(got) != 2 || got[0] != "agent-a" || got[1] != "agent-b" {
		t.Fatalf("batch agent IDs = %#v", got)
	}
	var result FleetUpdateResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Processed != 2 || result.Succeeded != 2 || result.Failed != 0 {
		t.Fatalf("unexpected result = %#v", result)
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

func TestHAStatusEndpoint(t *testing.T) {
	ts := testServer(t)
	ts.SetHAStatusFunc(func() HAStatus {
		return HAStatus{
			Mode:          "active-passive",
			NodeID:        "cp-1",
			Role:          "leader",
			LeaderID:      "cp-1",
			Healthy:       true,
			PeerCount:     2,
			Peers:         []string{"cp-2", "cp-3"},
			StateBackend:  "shared",
			FailoverReady: true,
		}
	})

	w := apiGet(ts, "/api/v1/control/ha")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var status HAStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if status.Mode != "active-passive" || !status.FailoverReady || status.PeerCount != 2 || status.UpdatedAt == "" {
		t.Fatalf("ha status = %#v", status)
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

func TestRBACCustomRolePermissions(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"ops-key"}, map[string]string{"ops-key": "responder"}, nil, true)
	ts.SetAPIAuthPermissions(map[string][]string{
		"responder": {"GET:/api/v1/control/fleet", "GET:/api/v1/control/ha"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/ha", nil)
	req.Header.Set("X-API-Key", "ops-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("custom role allowed status = %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/control/fleet", bytes.NewBufferString(`{"agent_id":"a1"}`))
	req.Header.Set("X-API-Key", "ops-key")
	w = apiServe(ts, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("custom role forbidden status = %d", w.Code)
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

func TestAuthAcceptsBearerToken(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/fleet", bytes.NewBufferString(`{"agent_id":"agent-a","group":"prod"}`))
	req.Header.Set("Authorization", "Bearer admin-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d: %s", w.Code, w.Body.String())
	}
	if got.Role != RoleAdmin {
		t.Fatalf("role = %q", got.Role)
	}
	if got.Actor != "SecOps On-Call (admin)" {
		t.Fatalf("actor = %q", got.Actor)
	}
}

func TestAuthRejectsMalformedBearerToken(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"analyst-key"}, map[string]string{"analyst-key": RoleAnalyst}, nil, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer")
	w := apiServe(ts, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d", w.Code)
	}
}

func TestStatusIncludesRuntimeDiagnostics(t *testing.T) {
	ts := testServer(t)
	ts.SetRuntimeDiagnostics(RuntimeDiagnostics{
		Version:                  "v-test",
		APIRest:                  ":18080",
		APIGRPC:                  ":18081",
		APIAuthEnabled:           true,
		TLSEnabled:               true,
		MTLSEnabled:              true,
		KernelAttachmentMode:     "lsm",
		PolicyEnabled:            true,
		PolicyEndpoint:           "https://control.example",
		PolicyBundleDir:          "/var/lib/providapt/policy",
		AppliedPolicyVersion:     7,
		ControlPlaneMode:         "cluster",
		ControlPlaneRole:         "leader",
		ControlPlaneStateBackend: "postgres://providapt",
		StorageEncrypted:         true,
		StorageKeyConfigured:     true,
		OutputDir:                "/var/log/providapt",
		SupportBundleEnabled:     true,
	})

	w := apiGet(ts, "/api/v1/status")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp struct {
		Diagnostics RuntimeDiagnostics `json:"diagnostics"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Diagnostics.KernelAttachmentMode != "lsm" {
		t.Fatalf("kernel attachment mode = %q", resp.Diagnostics.KernelAttachmentMode)
	}
	if !resp.Diagnostics.APIAuthEnabled || !resp.Diagnostics.StorageEncrypted {
		t.Fatalf("diagnostics security fields not preserved: %+v", resp.Diagnostics)
	}
	if resp.Diagnostics.ControlPlaneStateBackend != "postgres://providapt" {
		t.Fatalf("state backend = %q", resp.Diagnostics.ControlPlaneStateBackend)
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
	diff, ok := resp["diff"].([]interface{})
	if !ok || len(diff) == 0 {
		t.Fatalf("diff = %#v", resp["diff"])
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

func TestControlPlaneWriteRejectedOnFollower(t *testing.T) {
	ts := testServer(t)
	called := false
	ts.SetHAStatusFunc(func() HAStatus {
		return HAStatus{
			Mode:     "active-passive",
			NodeID:   "cp-b",
			Role:     "follower",
			LeaderID: "cp-a",
			Peers:    []string{"cp-a:18080", "cp-b:18080"},
			Healthy:  true,
		}
	})
	ts.SetPolicyActionFunc(func(req PolicyActionRequest) (PolicySummary, error) {
		called = true
		return PolicySummary{}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/policies", bytes.NewBufferString(`{"action":"publish"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("status code = %d body=%s", w.Code, w.Body.String())
	}
	if called {
		t.Fatal("policy action should not run on follower")
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["leader_id"] != "cp-a" || resp["leader_endpoint"] != "http://cp-a:18080" || !strings.Contains(resp["error"], "not leader") {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestControlPlaneWriteAllowedOnLeader(t *testing.T) {
	ts := testServer(t)
	called := false
	ts.SetHAStatusFunc(func() HAStatus {
		return HAStatus{
			Mode:     "active-passive",
			NodeID:   "cp-a",
			Role:     "leader",
			LeaderID: "cp-a",
			Healthy:  true,
		}
	})
	ts.SetPolicyActionFunc(func(req PolicyActionRequest) (PolicySummary, error) {
		called = true
		return PolicySummary{Version: 4, State: req.Action}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/policies", bytes.NewBufferString(`{"action":"publish"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d body=%s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("policy action should run on leader")
	}
}

func TestControlPlaneWriteRejectedWhenLeaderUnhealthy(t *testing.T) {
	ts := testServer(t)
	called := false
	ts.SetHAStatusFunc(func() HAStatus {
		return HAStatus{
			Mode:     "active-passive",
			NodeID:   "cp-a",
			Role:     "leader",
			LeaderID: "cp-a",
			Healthy:  false,
		}
	})
	ts.SetPolicyActionFunc(func(req PolicyActionRequest) (PolicySummary, error) {
		called = true
		return PolicySummary{}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/policies", bytes.NewBufferString(`{"action":"publish"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d body=%s", w.Code, w.Body.String())
	}
	if called {
		t.Fatal("policy action should not run on unhealthy leader")
	}
}

func TestControlPlaneReloadRejectedOnFollower(t *testing.T) {
	ts := testServer(t)
	called := false
	ts.SetHAStatusFunc(func() HAStatus {
		return HAStatus{
			Mode:     "active-passive",
			NodeID:   "cp-b",
			Role:     "follower",
			LeaderID: "cp-a",
			Healthy:  true,
		}
	})
	ts.SetReloadHandler(func() error {
		called = true
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/reload", nil)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("status code = %d body=%s", w.Code, w.Body.String())
	}
	if called {
		t.Fatal("reload should not run on follower")
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

func TestAlertWorkflowEndpointFallsBackToAlertLog(t *testing.T) {
	ts := testServer(t)
	dir := t.TempDir()
	alertPath := filepath.Join(dir, "alerts.ndjson")
	if err := os.WriteFile(alertPath, []byte(`{"AlertNodeID":"p:123","Severity":40,"Pattern":"DEEP_TAINT_CHAIN","Headline":"curl touched sensitive file","Reason":"simulated alert","DetectedAt":"2026-07-22T03:00:00Z"}`+"\n"), 0644); err != nil {
		t.Fatalf("write alert log: %v", err)
	}
	ts.SetAlertLogPath(alertPath)

	w := apiGet(ts, "/api/v1/control/alerts")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp AlertWorkflow
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Summary.Total != 1 || resp.Summary.Open != 1 {
		t.Fatalf("summary = %#v", resp.Summary)
	}
	if len(resp.Alerts) != 1 {
		t.Fatalf("alerts = %#v", resp.Alerts)
	}
	if resp.Alerts[0].ID != "p:123" || resp.Alerts[0].Severity != "HIGH" || resp.Alerts[0].Status != "open" {
		t.Fatalf("alert = %#v", resp.Alerts[0])
	}
}

func TestAlertWorkflowFallbackPersistsAnalystFeedback(t *testing.T) {
	ts := testServer(t)
	dir := t.TempDir()
	alertPath := filepath.Join(dir, "alerts.ndjson")
	if err := os.WriteFile(alertPath, []byte(`{"AlertNodeID":"p:123","Severity":40,"Pattern":"SCRIPT_CHILD","Headline":"bash spawned payload","DetectedAt":"2026-07-22T03:00:00Z"}`+"\n"), 0644); err != nil {
		t.Fatalf("write alert log: %v", err)
	}
	feedbackPath := filepath.Join(dir, "alert-feedback.ndjson")
	ts.SetAlertLogPath(alertPath)
	ts.SetAlertFeedbackPath(feedbackPath)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/alerts", bytes.NewBufferString(`{"action":"annotate","alert_id":"p:123","classification":"false_positive","note":"benign admin curl"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d: %s", w.Code, w.Body.String())
	}
	var updated AlertWorkflowItem
	if err := json.NewDecoder(w.Body).Decode(&updated); err != nil {
		t.Fatalf("decode update: %v", err)
	}
	if updated.Details["classification"] != "false_positive" || updated.Note != "benign admin curl" {
		t.Fatalf("updated alert = %#v", updated)
	}
	if data, err := os.ReadFile(feedbackPath); err != nil || !strings.Contains(string(data), `"classification":"false_positive"`) {
		t.Fatalf("feedback ledger data=%q err=%v", string(data), err)
	}

	w = apiGet(ts, "/api/v1/control/alerts")
	if w.Code != http.StatusOK {
		t.Fatalf("get status code = %d", w.Code)
	}
	var workflow AlertWorkflow
	if err := json.NewDecoder(w.Body).Decode(&workflow); err != nil {
		t.Fatalf("decode workflow: %v", err)
	}
	if len(workflow.Alerts) != 1 || workflow.Alerts[0].Details["classification"] != "false_positive" {
		t.Fatalf("workflow alerts = %#v", workflow.Alerts)
	}

	w = apiGet(ts, "/api/v1/control/alerts/feedback")
	if w.Code != http.StatusOK {
		t.Fatalf("feedback status code = %d", w.Code)
	}
	var feed AlertFeedbackFeed
	if err := json.NewDecoder(w.Body).Decode(&feed); err != nil {
		t.Fatalf("decode feedback: %v", err)
	}
	if feed.Summary.Total != 1 || feed.Summary.ByClass["false_positive"] != 1 {
		t.Fatalf("feedback feed = %#v", feed)
	}
}

func TestAlertWorkflowFallbackPersistsStatusForFiltering(t *testing.T) {
	ts := testServer(t)
	dir := t.TempDir()
	alertPath := filepath.Join(dir, "alerts.ndjson")
	if err := os.WriteFile(alertPath, []byte(`{"AlertNodeID":"a-closed","Severity":30,"Pattern":"NOISY","Headline":"noisy alert","DetectedAt":"2026-07-22T03:00:00Z"}`+"\n"), 0644); err != nil {
		t.Fatalf("write alert log: %v", err)
	}
	ts.SetAlertLogPath(alertPath)
	ts.SetAlertFeedbackPath(filepath.Join(dir, "alert-feedback.ndjson"))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/alerts", bytes.NewBufferString(`{"action":"close","alert_id":"a-closed","note":"duplicate campaign"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("close status code = %d: %s", w.Code, w.Body.String())
	}

	w = apiGet(ts, "/api/v1/control/alerts?status=closed")
	if w.Code != http.StatusOK {
		t.Fatalf("filter status code = %d", w.Code)
	}
	var workflow AlertWorkflow
	if err := json.NewDecoder(w.Body).Decode(&workflow); err != nil {
		t.Fatalf("decode workflow: %v", err)
	}
	if workflow.Summary.Total != 1 || len(workflow.Alerts) != 1 || workflow.Alerts[0].Status != "closed" {
		t.Fatalf("closed workflow = %#v", workflow)
	}
}

func TestGroundTruthEndpointLoadsJSONL(t *testing.T) {
	ts := testServer(t)
	dir := t.TempDir()
	alertPath := filepath.Join(dir, "alerts.ndjson")
	if err := os.WriteFile(alertPath, nil, 0644); err != nil {
		t.Fatalf("write alert log: %v", err)
	}
	gtDir := filepath.Join(dir, "ground-truth")
	if err := os.MkdirAll(gtDir, 0755); err != nil {
		t.Fatalf("mkdir ground truth: %v", err)
	}
	body := strings.Join([]string{
		`{"schema":"providapt.attack_ground_truth.v1","run_id":"r1","category":"compromise","step_index":2,"step_id":"step-02","step_name":"Execute payload","phase":"execution","tactic":"TA0002","tactic_id":"TA0002","tactic_name":"Execution","technique":"T1059.004 Unix Shell","technique_id":"T1059.004","technique_name":"Unix Shell","mitre_url":"https://attack.mitre.org/techniques/T1059/004/","command":"bash evil.sh","expected_event":"process_exec","expected_relation":"prov:wasInformedBy","actor":"bash","object":"pid:123","malicious":true}`,
		`{"schema":"providapt.attack_ground_truth.v1","run_id":"r1","phase":"benign","command":"whoami","expected_event":"process_exec","expected_relation":"prov:wasInformedBy","actor":"whoami","object":"stdout","malicious":false}`,
	}, "\n")
	if err := os.WriteFile(filepath.Join(gtDir, "r1.jsonl"), []byte(body), 0644); err != nil {
		t.Fatalf("write ground truth: %v", err)
	}
	ts.SetAlertLogPath(alertPath)

	w := apiGet(ts, "/api/v1/evaluation/ground-truth")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp GroundTruthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 2 || resp.Malicious != 1 || resp.Benign != 1 {
		t.Fatalf("summary = %#v", resp)
	}
	if resp.RunID != "r1" || resp.Records[0].ExpectedEvent != "process_exec" {
		t.Fatalf("ground truth response = %#v", resp)
	}
	if resp.Records[0].Category != "compromise" || resp.Records[0].StepID != "step-02" || resp.Records[0].TechniqueID != "T1059.004" || !strings.Contains(resp.Records[0].MITREURL, "/T1059/004/") {
		t.Fatalf("ground truth MITRE fields = %#v", resp.Records[0])
	}
}

func TestGroundTruthCorrelationEndpoint(t *testing.T) {
	ts := testServer(t)
	dir := t.TempDir()
	alertPath := filepath.Join(dir, "alerts.ndjson")
	if err := os.WriteFile(alertPath, []byte(`{"AlertNodeID":"p:123","Severity":40,"Pattern":"SCRIPT_CHILD","Headline":"bash spawned payload","DetectedAt":"2026-07-22T03:00:00Z"}`+"\n"), 0644); err != nil {
		t.Fatalf("write alert log: %v", err)
	}
	gtDir := filepath.Join(dir, "ground-truth")
	if err := os.MkdirAll(gtDir, 0755); err != nil {
		t.Fatalf("mkdir ground truth: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gtDir, "r1.jsonl"), []byte(`{"run_id":"r1","phase":"execution","command":"bash evil.sh","expected_event":"process_exec","expected_relation":"prov:wasInformedBy","actor":"bash","object":"pid:123","malicious":true}`+"\n"), 0644); err != nil {
		t.Fatalf("write ground truth: %v", err)
	}
	event := `{"schema_version":1,"type":"process_exec","process":{"pid":123,"comm":"bash"},"payload":{"cmdline":"bash evil.sh","child_pid":124},"timestamp_ns":1000}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "providapt-20260722T030000Z.ndjson"), []byte(event), 0644); err != nil {
		t.Fatalf("write event log: %v", err)
	}
	ts.SetAlertLogPath(alertPath)

	w := apiGet(ts, "/api/v1/evaluation/correlation")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp GroundTruthCorrelation
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 1 || resp.MatchedRecords != 1 || resp.EventMatches != 1 || resp.Traceable != 1 {
		t.Fatalf("correlation = %#v", resp)
	}
	if resp.Records[0].TraceNode != "p:123" {
		t.Fatalf("trace node = %q", resp.Records[0].TraceNode)
	}
}

func TestGroundTruthCorrelationRespectsExpectedEventType(t *testing.T) {
	ts := testServer(t)
	dir := t.TempDir()
	alertPath := filepath.Join(dir, "alerts.ndjson")
	if err := os.WriteFile(alertPath, nil, 0644); err != nil {
		t.Fatalf("write alert log: %v", err)
	}
	gtDir := filepath.Join(dir, "ground-truth")
	if err := os.MkdirAll(gtDir, 0755); err != nil {
		t.Fatalf("mkdir ground truth: %v", err)
	}
	truth := `{"run_id":"r1","phase":"initial_access","command":"create payload script","expected_event":"file_write","expected_relation":"prov:wasGeneratedBy","actor":"bash","object":"/tmp/evil.sh","malicious":true}` + "\n"
	if err := os.WriteFile(filepath.Join(gtDir, "r1.jsonl"), []byte(truth), 0644); err != nil {
		t.Fatalf("write ground truth: %v", err)
	}
	events := strings.Join([]string{
		`{"schema_version":1,"type":"file_open","process":{"pid":123,"comm":"bash"},"payload":{"pathname":"/tmp/evil.sh"},"timestamp_ns":1000}`,
		`{"schema_version":1,"type":"file_write","process":{"pid":123,"comm":"bash"},"payload":{"pathname":"/tmp/evil.sh"},"timestamp_ns":2000}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "providapt-20260722T030000Z.ndjson"), []byte(events), 0644); err != nil {
		t.Fatalf("write event log: %v", err)
	}
	ts.SetAlertLogPath(alertPath)

	w := apiGet(ts, "/api/v1/evaluation/correlation")
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp GroundTruthCorrelation
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.EventMatches != 1 || len(resp.Records) != 1 || len(resp.Records[0].EventMatches) != 1 {
		t.Fatalf("correlation = %#v", resp)
	}
	if got := resp.Records[0].EventMatches[0].Type; got != "file_write" {
		t.Fatalf("matched event type = %q", got)
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/alerts", bytes.NewBufferString(`{"action":"annotate","alert_id":"a-1","classification":"true_positive","note":"confirmed simulation"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotReq.Action != "annotate" || gotReq.AlertID != "a-1" || gotReq.Classification != "true_positive" || gotReq.Note != "confirmed simulation" {
		t.Fatalf("request = %#v", gotReq)
	}
}

func TestAlertWorkflowBulkActionEndpoint(t *testing.T) {
	ts := testServer(t)
	var got []string
	ts.SetAlertWorkflowActionFunc(func(req AlertWorkflowActionRequest) (AlertWorkflowItem, error) {
		got = append(got, req.AlertID)
		return AlertWorkflowItem{ID: req.AlertID, Status: "closed"}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/control/alerts", bytes.NewBufferString(`{"action":"close","alert_ids":["a-1","a-2","a-1"],"note":"duplicate campaign"}`))
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d: %s", w.Code, w.Body.String())
	}
	var resp AlertWorkflowActionResult
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Processed != 2 || resp.Succeeded != 2 || len(resp.Alerts) != 2 {
		t.Fatalf("bulk result = %#v", resp)
	}
	if len(got) != 2 || got[0] != "a-1" || got[1] != "a-2" {
		t.Fatalf("bulk IDs = %#v", got)
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
	hasFileAttrs := false
	for _, el := range resp.Elements {
		if el.Group == "nodes" {
			hasNode = true
			if el.Data.ID == "" {
				t.Error("node missing id")
			}
			if el.Data.NodeType == "file" && el.Data.Attributes["pathname"] == "/etc/shadow" && el.Data.Attributes["device"] == "8:3" {
				hasFileAttrs = true
			}
		}
		if el.Group == "edges" {
			hasEdge = true
			if el.Data.Source == "" || el.Data.Target == "" {
				t.Error("edge missing source/target")
			}
			if el.Data.Attributes["relation"] == "" {
				t.Error("edge missing relation attribute")
			}
		}
	}
	if !hasNode {
		t.Error("no node elements")
	}
	if !hasEdge {
		t.Error("no edge elements")
	}
	if !hasFileAttrs {
		t.Error("file node missing pathname/device attributes")
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

func TestInvestigationReportEndpoint(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/investigation/report?pid=100&direction=backward&depth=3")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}

	var report InvestigationReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.StartNode != "p:100" || report.Direction != "backward" {
		t.Fatalf("unexpected report identity: %+v", report)
	}
	if report.NodeCount == 0 || len(report.Nodes) == 0 {
		t.Fatalf("expected investigation nodes: %+v", report)
	}
	if report.RiskSummary == "" || len(report.KeyObservations) == 0 {
		t.Fatalf("expected report summary: %+v", report)
	}
}

func TestInvestigationReportMarkdown(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/investigation/report?node=p:100&format=markdown")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/markdown") {
		t.Fatalf("content type = %q", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "ProvidAPT Investigation Report") {
		t.Fatalf("unexpected markdown: %s", w.Body.String())
	}
}

func TestRBACAuditorInvestigationReportAllowed(t *testing.T) {
	ts := testServer(t)
	ts.SetAPIAuth([]string{"auditor-key"}, map[string]string{"auditor-key": RoleAuditor}, nil, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/investigation/report?pid=100", nil)
	req.Header.Set("X-API-Key", "auditor-key")
	w := apiServe(ts, req)
	if w.Code != http.StatusOK {
		t.Fatalf("auditor investigation report status = %d: %s", w.Code, w.Body.String())
	}
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

func TestAlertSVGViewerSubroute(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/alerts/p%3A100/svg/view")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("content-type = %q", got)
	}
	body := w.Body.String()
	for _, want := range []string{"ProvidAPT Trace Viewer", "Zoom In", "Fit Width", "/api/v1/alerts/p:100/svg"} {
		if !strings.Contains(body, want) {
			t.Fatalf("viewer missing %q in body: %s", want, body)
		}
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
	if got := w.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
		t.Fatalf("CORS headers = %q", got)
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
	if !strings.Contains(string(svg), "Event Structure") {
		t.Error("SVG missing event structure table")
	}
	if !strings.Contains(string(svg), `preserveAspectRatio="xMidYMin meet"`) || !strings.Contains(string(svg), `margin:0 auto`) {
		t.Error("SVG missing responsive centered viewport")
	}
	if !strings.Contains(string(svg), "categories") || !strings.Contains(string(svg), "Discovery or Credential Access / File Reads") {
		t.Error("SVG missing categorized event summary")
	}
	if !strings.Contains(string(svg), "file_open") {
		t.Error("SVG missing event name")
	}
	if !strings.Contains(string(svg), "path=/etc/shadow") {
		t.Error("SVG missing target path detail")
	}
	if !strings.Contains(string(svg), "cmdline=cat /etc/shadow") {
		t.Error("SVG missing process command line detail")
	}
	if !strings.Contains(string(svg), "ppid=1") {
		t.Error("SVG missing parent PID detail")
	}
	if !strings.Contains(string(svg), "Causal direction is rendered as source -&gt; target") {
		t.Error("SVG missing direction explanation")
	}
	if !strings.Contains(string(svg), "Tree layout is left-to-right") {
		t.Error("SVG missing tree layout explanation")
	}
	if !strings.Contains(string(svg), `marker-end: url(#arrow-read)`) {
		t.Error("SVG missing relation-specific arrow marker")
	}
	if !strings.Contains(string(svg), `<path d="M`) {
		t.Error("SVG should render routed paths instead of straight-only lines")
	}
	if strings.Contains(string(svg), "cmdline=cat /etc/sh...") {
		t.Error("SVG should not truncate provenance cmdline details with ellipsis")
	}
	if !strings.Contains(string(svg), `edge-label-read`) {
		t.Error("SVG missing operation-specific edge label class")
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

func TestSVGFocusedGraph(t *testing.T) {
	g := testGraph(t)
	g.AddEvent(&collector.Event{
		Type:        syscall.EventFileOpen,
		TimestampNS: 3000,
		PID:         999,
		Pathname:    "/unrelated/noise",
		Inode:       9000,
		DevMajor:    8,
		DevMinor:    3,
		Comm:        "noise",
	})

	svg := string(generateAlertSVG("p:100", g))
	if !strings.Contains(svg, "Focused scope: p:100") {
		t.Error("SVG missing focused scope")
	}
	if strings.Contains(svg, "/unrelated/noise") {
		t.Error("focused SVG includes unrelated graph branch")
	}
}

// ── Helpers tests ──────────────────────────────────────────

func TestSVGTreeLayoutKeepsCrossLinksReadable(t *testing.T) {
	nodes := []*provenance.Node{
		{ID: "p:1", Label: "parent", Subtype: "process"},
		{ID: "p:2", Label: "child-a", Subtype: "process"},
		{ID: "p:3", Label: "child-b", Subtype: "process"},
		{ID: "f:1", Label: "/tmp/payload", Subtype: "file"},
	}
	edges := []*provenance.Edge{
		{ID: "e1", Source: "p:1", Target: "p:2", Relation: provenance.ProvWasInformedBy, Attributes: map[string]interface{}{"event": "process_fork"}},
		{ID: "e2", Source: "p:1", Target: "p:3", Relation: provenance.ProvWasInformedBy, Attributes: map[string]interface{}{"event": "process_fork"}},
		{ID: "e3", Source: "p:2", Target: "f:1", Relation: provenance.ProvWasGeneratedBy, Attributes: map[string]interface{}{"event": "file_write"}},
		{ID: "e4", Source: "p:3", Target: "f:1", Relation: provenance.ProvUsed, Attributes: map[string]interface{}{"event": "file_open"}},
	}
	layout := layoutGraph(nodes, edges)
	byID := map[string]svgNode{}
	for _, node := range layout.nodes {
		byID[node.id] = node
	}
	if byID["p:2"].x <= byID["p:1"].x || byID["f:1"].x <= byID["p:2"].x {
		t.Fatalf("expected left-to-right tree coordinates: %#v", byID)
	}
	treeEdges := 0
	crossEdges := 0
	for _, edge := range layout.edges {
		if edge.tree {
			treeEdges++
		} else {
			crossEdges++
		}
	}
	if treeEdges != 3 || crossEdges != 1 {
		t.Fatalf("tree/cross edge split = %d/%d, want 3/1", treeEdges, crossEdges)
	}
	svg := string(renderSVG(layout))
	if !strings.Contains(svg, `class="edge edge-cross`) || !strings.Contains(svg, `data-tree="false"`) {
		t.Fatalf("SVG should preserve non-tree links as dashed cross-links: %s", svg)
	}
	if !strings.Contains(svg, "Execution / Process Activity") || !strings.Contains(svg, "Persistence or Collection / File Writes") {
		t.Fatalf("SVG should categorize event groups: %s", svg)
	}
}

func TestSVGNodeSizeAdaptsToLongContent(t *testing.T) {
	longCmd := "bash -lc curl --connect-timeout 2 http://127.0.0.1:1/very/long/path/that/should/wrap/instead/of/overlap"
	node := &provenance.Node{
		ID:      "p:4242",
		Label:   "curl-with-long-command",
		Subtype: provenance.SubProcess,
		Attributes: map[string]interface{}{
			"pid":     4242,
			"comm":    "bash",
			"cmdline": longCmd,
		},
	}
	svgNode := makeSVGNode(node, 0)
	if svgNode.w <= minNodeW {
		t.Fatalf("node width = %d, want adaptive width above minimum", svgNode.w)
	}
	if svgNode.h <= minNodeH {
		t.Fatalf("node height = %d, want adaptive height above minimum", svgNode.h)
	}
	rendered := renderNodeText(svgNode)
	if strings.Contains(rendered, "...") {
		t.Fatalf("node text should wrap without ellipsis: %s", rendered)
	}
}

func TestSVGFoldsDenseSameLayerNodes(t *testing.T) {
	nodes := []*provenance.Node{{ID: "p:root", Label: "root", Subtype: "process"}}
	edges := []*provenance.Edge{}
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("f:%d", i)
		nodes = append(nodes, &provenance.Node{ID: id, Label: fmt.Sprintf("/tmp/file-%d", i), Subtype: "file"})
		edges = append(edges, &provenance.Edge{
			ID:         fmt.Sprintf("e:%d", i),
			Source:     "p:root",
			Target:     id,
			Relation:   provenance.ProvUsed,
			Attributes: map[string]interface{}{"event": "file_open"},
		})
	}
	layout := layoutGraph(nodes, edges)
	if layout.collapsedNodes == 0 || len(layout.clusters) == 0 {
		t.Fatalf("expected dense layer folding, collapsed=%d clusters=%d", layout.collapsedNodes, len(layout.clusters))
	}
	svg := string(renderSVG(layout))
	if !strings.Contains(svg, "folded - depth") || !strings.Contains(svg, "folded clusters summarize same-layer/type nodes") {
		t.Fatalf("SVG missing folded cluster explanation: %s", svg)
	}
	if !strings.Contains(svg, "data-folded-count") || !strings.Contains(svg, "data-members") || !strings.Contains(svg, "data-reason") {
		t.Fatalf("SVG missing folded cluster metadata: %s", svg)
	}
}

func TestLoadAlertsReadsRotatedNDJSON(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "alerts-20260722T010000Z.ndjson")
	active := filepath.Join(dir, "alerts.ndjson")
	if err := os.WriteFile(archive, []byte(`{"id":"old","status":"open"}`+"\n"), 0644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	if err := os.WriteFile(active, []byte(`{"id":"active","status":"open"}`+"\n"), 0644); err != nil {
		t.Fatalf("write active: %v", err)
	}

	alerts := loadAlerts(active)
	if len(alerts) != 2 {
		t.Fatalf("alerts = %d, want 2: %#v", len(alerts), alerts)
	}
	if alerts[0]["id"] != "old" || alerts[1]["id"] != "active" {
		t.Fatalf("alert order/content = %#v", alerts)
	}
}

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
