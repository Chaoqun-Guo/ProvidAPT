// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package appsync

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ── Probe injection tests ───────────────────────────────────

func TestNewProbeManager(t *testing.T) {
	pm := NewProbeManager()
	if pm == nil {
		t.Fatal("NewProbeManager returned nil")
	}
}

func TestDetectRunningApps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DetectRunningApps reads /proc — not available on Windows")
	}
	pm := NewProbeManager()
	apps, err := pm.DetectRunningApps()
	if err != nil {
		t.Fatalf("DetectRunningApps: %v", err)
	}
	t.Logf("Detected %d apps", len(apps))
	for _, app := range apps {
		t.Logf("  %s (PID %d, %s, %d probes)",
			app.AppName, app.PID, app.Binary, len(app.Probes))
	}
}

func TestKnownAppNames(t *testing.T) {
	pm := NewProbeManager()
	names := pm.knownAppNames()
	if len(names) == 0 {
		t.Error("no known apps registered")
	}
	t.Logf("Known apps: %v", names)
}

func TestAttachAll(t *testing.T) {
	pm := NewProbeManager()
	plans := pm.AttachAll()
	t.Logf("Attachment plans: %d", len(plans))
	for _, p := range plans {
		t.Logf("  uprobe %s:%s (%s)", p.Binary, p.Symbol, p.Type)
	}
}

func TestSummary(t *testing.T) {
	pm := NewProbeManager()
	summary := pm.Summary()
	if !strings.Contains(summary, "No supported") && !strings.Contains(summary, "PID") {
		t.Errorf("unexpected summary: %s", summary)
	}
	t.Logf("Summary: %s", summary)
}

// ── Request tracker tests ───────────────────────────────────

func TestNewRequestTracker(t *testing.T) {
	rt := NewRequestTracker()
	if rt == nil {
		t.Fatal("NewRequestTracker returned nil")
	}
}

func TestStartEndRequest(t *testing.T) {
	rt := NewRequestTracker()
	rt.StartRequest(100, 200, "nginx", "req-001", "GET", "/admin/config")
	if rt.ActiveCount() != 1 {
		t.Errorf("active = %d", rt.ActiveCount())
	}

	rt.EndRequest(100)
	if rt.ActiveCount() != 0 {
		t.Errorf("active after end = %d", rt.ActiveCount())
	}
	if rt.RequestCount() != 1 {
		t.Errorf("history = %d", rt.RequestCount())
	}
}

func TestGetRequest(t *testing.T) {
	rt := NewRequestTracker()
	rt.StartRequest(100, 200, "nginx", "req-002", "POST", "/api/login")

	info := rt.GetRequest(100)
	if info == nil {
		t.Fatal("GetRequest returned nil")
	}
	if info.RequestID != "req-002" {
		t.Errorf("RequestID = %s", info.RequestID)
	}
	if info.Method != "POST" {
		t.Errorf("Method = %s", info.Method)
	}

	// Non-existent TID
	info = rt.GetRequest(999)
	if info != nil {
		t.Error("non-existent TID should return nil")
	}
}

func TestGetOrCreateRequestID(t *testing.T) {
	rt := NewRequestTracker()
	rt.StartRequest(100, 200, "nginx", "req-003", "GET", "/")

	// With active request
	id := rt.GetOrCreateRequestID(100, 200, "nginx")
	if id != "req-003" {
		t.Errorf("got %s, want req-003", id)
	}

	// Without active request — synthetic ID
	id = rt.GetOrCreateRequestID(999, 500, "bash")
	if !strings.HasPrefix(id, "sys:bash:500") {
		t.Errorf("synthetic ID = %s", id)
	}
}

func TestConcurrentRequests(t *testing.T) {
	rt := NewRequestTracker()
	for i := 0; i < 10; i++ {
		tid := uint32(100 + i)
		rt.StartRequest(tid, uint32(200+i), "nginx",
			fmt.Sprintf("req-%04d", i), "GET", "/path")
	}
	if rt.ActiveCount() != 10 {
		t.Errorf("active = %d", rt.ActiveCount())
	}
	for i := 0; i < 10; i++ {
		rt.EndRequest(uint32(100 + i))
	}
	if rt.ActiveCount() != 0 {
		t.Errorf("active after all ended = %d", rt.ActiveCount())
	}
}

// ── Semantic merger tests ───────────────────────────────────

func TestNewSemanticMerger(t *testing.T) {
	sm := NewSemanticMerger()
	if sm == nil {
		t.Fatal("NewSemanticMerger returned nil")
	}
}

func TestBeginEndTransaction(t *testing.T) {
	sm := NewSemanticMerger()
	rt := NewRequestTracker()
	rt.StartRequest(100, 200, "nginx", "txn-001", "GET", "/admin")

	info := rt.GetRequest(100)
	txn := sm.BeginTransaction(info)
	if txn == nil {
		t.Fatal("BeginTransaction returned nil")
	}
	if txn.Label != "GET /admin" {
		t.Errorf("label = %s", txn.Label)
	}
	if sm.PendingCount() != 1 {
		t.Errorf("pending = %d", sm.PendingCount())
	}

	rt.EndRequest(100)
	completed := sm.EndTransaction("txn-001")
	if completed == nil {
		t.Fatal("EndTransaction returned nil")
	}
	if completed.Duration == "" {
		t.Error("duration should be set")
	}
}

func TestRecordFileAccess(t *testing.T) {
	sm := NewSemanticMerger()
	rt := NewRequestTracker()
	rt.StartRequest(100, 200, "nginx", "txn-file", "GET", "/config")

	info := rt.GetRequest(100)
	sm.BeginTransaction(info)

	// Record some file accesses
	sm.RecordFileAccess(100, rt, "/etc/nginx/nginx.conf", false)
	sm.RecordFileAccess(100, rt, "/etc/shadow", false)
	sm.RecordFileAccess(100, rt, "/tmp/evil.sh", true)

	rt.EndRequest(100)
	sm.EndTransaction("txn-file")

	txns := sm.CompletedTransactions()
	if len(txns) != 1 {
		t.Fatalf("completed = %d", len(txns))
	}
	txn := txns[0]
	if len(txn.FilesRead) != 2 {
		t.Errorf("files read = %d", len(txn.FilesRead))
	}
	if len(txn.FilesWritten) != 1 {
		t.Errorf("files written = %d", len(txn.FilesWritten))
	}
}

func TestRecordNetworkConnect(t *testing.T) {
	sm := NewSemanticMerger()
	rt := NewRequestTracker()
	rt.StartRequest(100, 200, "nginx", "txn-net", "POST", "/api/data")

	info := rt.GetRequest(100)
	sm.BeginTransaction(info)

	sm.RecordNetworkConnect(100, rt, "5.6.7.8:443")
	sm.RecordNetworkConnect(100, rt, "10.0.0.1:80")

	rt.EndRequest(100)
	sm.EndTransaction("txn-net")

	txns := sm.CompletedTransactions()
	if len(txns) != 1 {
		t.Fatal("expected 1 transaction")
	}
	if len(txns[0].NetConnects) != 2 {
		t.Errorf("net connects = %d", len(txns[0].NetConnects))
	}
}

func TestBuildGraphNode(t *testing.T) {
	txn := &TransactionNode{
		ID: "txn:42", Label: "GET /admin",
		Method: "GET", Path: "/admin",
		AppName: "nginx", PID: 100,
		StartTime: time.Now(),
		Duration:  "50ms",
	}
	node := txn.BuildGraphNode()
	if node == nil {
		t.Fatal("BuildGraphNode returned nil")
	}
	if node.Subtype != "transaction" {
		t.Errorf("subtype = %s", node.Subtype)
	}
	if node.Label != "GET /admin" {
		t.Errorf("label = %s", node.Label)
	}
	if node.Attributes["method"] != "GET" {
		t.Errorf("method = %v", node.Attributes["method"])
	}
}

func TestIntegrationSummary(t *testing.T) {
	sm := NewSemanticMerger()
	summary := sm.Summary()
	if !strings.Contains(summary, "Transactions:") {
		t.Error("summary format incorrect")
	}
}

func TestEmptyEndTransaction(t *testing.T) {
	sm := NewSemanticMerger()
	txn := sm.EndTransaction("nonexistent")
	if txn != nil {
		t.Error("expected nil for non-existent transaction")
	}
}

// ── Integration test ────────────────────────────────────────

func TestAppSyncIntegration(t *testing.T) {
	// Simulate a complete flow: probe detection → request tracking → semantic merge

	// Step 1: Detect apps
	pm := NewProbeManager()
	apps, _ := pm.DetectRunningApps()
	t.Logf("Step 1: Detected %d apps", len(apps))

	// Step 2: Track a request
	rt := NewRequestTracker()
	rt.StartRequest(100, 200, "nginx", "integ-001", "GET", "/admin/config")
	t.Logf("Step 2: Request started (active=%d)", rt.ActiveCount())

	// Step 3: Merge into transaction
	sm := NewSemanticMerger()
	info := rt.GetRequest(100)
	txn := sm.BeginTransaction(info)
	t.Logf("Step 3: Transaction begun: %s", txn.Label)

	// Step 4: Record file/network activity
	sm.RecordFileAccess(100, rt, "/etc/shadow", false)
	sm.RecordFileAccess(100, rt, "/tmp/malware.sh", true)
	sm.RecordNetworkConnect(100, rt, "5.6.7.8:4443")
	t.Logf("Step 4: Activity recorded (files=%d, net=%d)",
		len(txn.FilesRead)+len(txn.FilesWritten), len(txn.NetConnects))

	// Step 5: End transaction
	rt.EndRequest(100)
	completed := sm.EndTransaction("integ-001")
	t.Logf("Step 5: Transaction completed: %s (%s)", completed.Label, completed.Duration)

	// Step 6: Build provenance node
	node := completed.BuildGraphNode()
	t.Logf("Step 6: Graph node: id=%s type=%s label=%s",
		node.ID, node.Subtype, node.Label)

	// Verify the chain
	if node.Subtype != "transaction" {
		t.Error("expected transaction subtype")
	}
	if node.Attributes["method"] != "GET" {
		t.Errorf("method = %v", node.Attributes["method"])
	}

	t.Log("AppSync integration test passed")
}
