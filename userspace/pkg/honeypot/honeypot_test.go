package honeypot

import (
	"strings"
	"testing"
)

// ── Honey path tests ────────────────────────────────────────

func TestDefaultPaths(t *testing.T) {
	paths := DefaultHoneyPaths()
	if len(paths) == 0 {
		t.Fatal("no default honey paths")
	}
	t.Logf("Default honey paths: %d", len(paths))
	for _, p := range paths {
		t.Logf("  %s [%s] %s", p.Path, p.Category, p.Description)
	}
}

func TestNewManager(t *testing.T) {
	mgr := NewManager()
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	stats := mgr.Stats()
	if stats["total_paths"].(int) == 0 {
		t.Error("no paths loaded")
	}
	t.Logf("Manager: %d paths", stats["total_paths"])
}

func TestAddPath(t *testing.T) {
	mgr := NewManager()
	mgr.AddPath(HoneyPath{Path: "/custom/honey/path.txt", Description: "custom"})
	if len(mgr.Paths()) != len(DefaultHoneyPaths())+1 {
		t.Errorf("paths = %d", len(mgr.Paths()))
	}
}

func TestHashPath(t *testing.T) {
	path := "/root/.aws/credentials"
	hash := HashPath(path)
	if len(hash) != 16 {
		t.Errorf("hash length = %d", len(hash))
	}
	// Same path → same hash
	hash2 := HashPath(path)
	if hash != hash2 {
		t.Error("hash not deterministic")
	}
}

func TestDeployHashes(t *testing.T) {
	mgr := NewManager()
	hashes := mgr.DeployHashes()
	if len(hashes) != len(DefaultHoneyPaths()) {
		t.Errorf("hashes = %d, want %d", len(hashes), len(DefaultHoneyPaths()))
	}
	for hash, path := range hashes {
		if len(hash) != 16 {
			t.Errorf("hash length = %d for %s", len(hash), path)
		}
	}
	t.Logf("Deployable hashes: %d", len(hashes))
}

func TestIsHoneyPath(t *testing.T) {
	mgr := NewManager()
	hash := HashPath("/root/.aws/credentials")
	found, ok := mgr.IsHoneyPath(hash)
	if !ok {
		t.Error("known path should be found")
	}
	if !strings.Contains(found, "credentials") {
		t.Errorf("found = %s", found)
	}

	_, ok = mgr.IsHoneyPath("nonexistenthash123")
	if ok {
		t.Error("unknown hash should not be found")
	}
}

// ── Trigger tests ───────────────────────────────────────────

func TestNewTrigger(t *testing.T) {
	tr := NewTrigger(nil)
	if tr == nil {
		t.Fatal("NewTrigger returned nil")
	}
}

func TestOnAccessGeneratesAlert(t *testing.T) {
	tr := NewTrigger(nil)
	alert := tr.OnAccess("/etc/shadow.bak", 100, "cat", "read")
	if alert == nil {
		t.Fatal("OnAccess returned nil")
	}
	if alert.Severity != "CRITICAL" {
		t.Errorf("severity = %s", alert.Severity)
	}
	if alert.PID != 100 {
		t.Errorf("PID = %d", alert.PID)
	}
	if alert.Comm != "cat" {
		t.Errorf("Comm = %s", alert.Comm)
	}
}

func TestOnAccessSilent(t *testing.T) {
	tr := NewTrigger(nil)
	alert := tr.OnAccess("/root/.ssh/id_rsa", 200, "ssh", "stat")
	if alert.Category != "cred" {
		t.Errorf("category = %s", alert.Category)
	}
	if alert.Action != "stat" {
		t.Errorf("action = %s", alert.Action)
	}
}

func TestAlertsList(t *testing.T) {
	tr := NewTrigger(nil)
	tr.OnAccess("/path1", 1, "p1", "read")
	tr.OnAccess("/path2", 2, "p2", "stat")

	alerts := tr.Alerts()
	if len(alerts) != 2 {
		t.Errorf("alerts = %d", len(alerts))
	}
}

func TestRecentAlerts(t *testing.T) {
	tr := NewTrigger(nil)
	tr.OnAccess("/tmp/dump.sql", 100, "mysql", "open")
	alerts := tr.RecentAlerts(3600)
	if len(alerts) == 0 {
		t.Error("expected recent alerts")
	}
}

func TestIsProcessTriggered(t *testing.T) {
	tr := NewTrigger(nil)
	tr.OnAccess("/etc/shadow.bak", 500, "python", "read")

	if !tr.IsProcessTriggered(500) {
		t.Error("PID 500 should be triggered")
	}
	if tr.IsProcessTriggered(999) {
		t.Error("PID 999 should not be triggered")
	}
}

func TestEscalationConfig(t *testing.T) {
	cfg := DefaultEscalationConfig()
	if !cfg.EnableFullAudit {
		t.Error("default should enable full audit")
	}
	if cfg.SandboxPath != "" {
		t.Errorf("sandbox = %s", cfg.SandboxPath)
	}
}

func TestAlertHandlerCallback(t *testing.T) {
	called := false
	handler := func(alert *HoneyAlert) {
		called = true
	}

	tr := NewTrigger(&EscalationConfig{
		AlertHandlers: []AlertHandler{handler},
	})
	tr.OnAccess("/test/path", 999, "test", "read")
	if !called {
		t.Error("alert handler was not called")
	}
}

func TestProcessAlertSummary(t *testing.T) {
	tr := NewTrigger(nil)
	summary := tr.ProcessAlertSummary()
	if !strings.Contains(summary, "No honey pot") {
		t.Errorf("empty summary = %s", summary)
	}

	tr.OnAccess("/etc/shadow.bak", 100, "cat", "read")
	summary = tr.ProcessAlertSummary()
	if !strings.Contains(summary, "cat") {
		t.Errorf("summary = %s", summary)
	}
	t.Logf("Summary:\n%s", summary)
}

func TestHoneyEventType(t *testing.T) {
	if HoneyEventType != 210 {
		t.Errorf("HoneyEventType = %d", HoneyEventType)
	}
}

// ── Integration test ────────────────────────────────────────

func TestHoneypotIntegration(t *testing.T) {
	t.Log("=== Honey Pot Active Defense Test ===")

	// Initialize manager
	mgr := NewManager()
	t.Logf("Loaded %d honey paths", len(mgr.Paths()))

	// Compute hashes for BPF map
	hashes := mgr.DeployHashes()
	t.Logf("Computed %d deployable hashes", len(hashes))

	// Verify a specific path
	hash := HashPath("/etc/shadow.bak")
	if path, ok := mgr.IsHoneyPath(hash); ok {
		t.Logf("Verified: %s → hash=%s", path, hash)
	}

	// Simulate trigger
	tr := NewTrigger(nil)
	alert := tr.OnAccess("/root/.aws/credentials", 1234, "curl", "read")
	if alert == nil {
		t.Fatal("alert not generated")
	}

	// Verify alert details
	t.Logf("Alert: PID=%d Comm=%s Path=%s Severity=%s",
		alert.PID, alert.Comm, alert.Path, alert.Severity)
	if alert.Severity != "CRITICAL" {
		t.Error("all honey alerts should be CRITICAL")
	}

	// Verify the process is tracked
	if !tr.IsProcessTriggered(1234) {
		t.Error("process should be marked as triggered")
	}

	// Summary
	summary := tr.ProcessAlertSummary()
	t.Logf("Summary: %s", summary)

	t.Log("=== Honey Pot Test Complete ===")
}
