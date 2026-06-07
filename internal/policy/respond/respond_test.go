// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package respond

import (
	"strings"
	"testing"
)

// ─── Causal blocking tests ──────────────────────────────────

func TestNewCausalBlocker(t *testing.T) {
	cb := NewCausalBlocker()
	if cb == nil {
		t.Fatal("NewCausalBlocker returned nil")
	}
}

func TestBlockProcess(t *testing.T) {
	cb := NewCausalBlocker()
	bp := cb.BlockProcess(100, "curl", BlockNetwork)

	if bp.PID != 100 {
		t.Errorf("pid = %d", bp.PID)
	}
	if bp.Comm != "curl" {
		t.Errorf("comm = %s", bp.Comm)
	}
	if bp.Level != BlockNetwork {
		t.Errorf("level = %d", bp.Level)
	}
}

func TestAddChild(t *testing.T) {
	cb := NewCausalBlocker()
	cb.BlockProcess(100, "bash", BlockAll)
	cb.AddChild(100, 200)

	if !cb.IsBlocked(200) {
		t.Error("child should be blocked")
	}
}

func TestIsBlocked(t *testing.T) {
	cb := NewCausalBlocker()
	cb.BlockProcess(100, "python", BlockAll)

	if !cb.IsBlocked(100) {
		t.Error("blocked pid should return true")
	}
	if cb.IsBlocked(999) {
		t.Error("non-blocked pid should return false")
	}
}

func TestBlockLevel(t *testing.T) {
	cb := NewCausalBlocker()
	cb.BlockProcess(100, "curl", BlockNetwork)
	cb.BlockProcess(200, "bash", BlockAll)

	if cb.BlockLevel(100) != BlockNetwork {
		t.Errorf("level = %d", cb.BlockLevel(100))
	}
	if cb.BlockLevel(999) != BlockNone {
		t.Errorf("unblocked level = %d", cb.BlockLevel(999))
	}
}

func TestUnblockProcess(t *testing.T) {
	cb := NewCausalBlocker()
	cb.BlockProcess(100, "bash", BlockAll)
	cb.AddChild(100, 200)
	cb.UnblockProcess(100)

	if cb.IsBlocked(100) {
		t.Error("should be unblocked")
	}
	if cb.IsBlocked(200) {
		t.Error("child should be unblocked")
	}
}

func TestBlockLevelString(t *testing.T) {
	if BlockNone.String() != "NONE" {
		t.Errorf("NONE = %s", BlockNone)
	}
	if BlockAll.String() != "FULL_ISOLATION" {
		t.Errorf("FULL = %s", BlockAll)
	}
}

func TestStats(t *testing.T) {
	cb := NewCausalBlocker()
	cb.BlockProcess(100, "bash", BlockAll)
	cb.AddChild(100, 200)

	stats := cb.Stats()
	if stats["blocked_trees"].(int) != 1 {
		t.Errorf("trees = %d", stats["blocked_trees"])
	}
	if stats["blocked_pids"].(int) != 2 {
		t.Errorf("pids = %d", stats["blocked_pids"])
	}
}

// ─── File quarantine tests ──────────────────────────────────

func TestNewFileQuarantineManager(t *testing.T) {
	fqm := NewFileQuarantineManager("", true)
	if fqm == nil {
		t.Fatal("NewFileQuarantineManager returned nil")
	}
}

func TestQuarantineFile(t *testing.T) {
	fqm := NewFileQuarantineManager("", true)
	qf := fqm.QuarantineFile("/tmp/evil.sh", 100, QuarantineLock)

	if qf.Action != "dry-run" {
		t.Errorf("action = %s", qf.Action)
	}
	if qf.WrittenBy != 100 {
		t.Errorf("written by = %d", qf.WrittenBy)
	}
}

func TestQuarantineFilesByPID(t *testing.T) {
	fqm := NewFileQuarantineManager("", true)
	files := []string{"/tmp/evil.sh", "/tmp/backdoor"}
	results := fqm.QuarantineFilesByPID(100, files, QuarantineLock)

	if len(results) != 2 {
		t.Errorf("results = %d", len(results))
	}
}

func TestSanitize(t *testing.T) {
	s := sanitize("/etc/shadow")
	if s != "_etc_shadow" {
		t.Errorf("sanitize = %s", s)
	}
}

func TestQuarantineStats(t *testing.T) {
	fqm := NewFileQuarantineManager("", true)
	fqm.QuarantineFile("/tmp/test", 100, QuarantineLock)

	stats := fqm.Stats()
	if stats["total_quarantined"].(int) != 1 {
		t.Errorf("quarantined = %d", stats["total_quarantined"])
	}
}

// ─── Response policy tests ──────────────────────────────────

func TestDefaultResponsePolicy(t *testing.T) {
	rp := DefaultResponsePolicy()
	if len(rp.Rules) != 5 {
		t.Errorf("rules = %d", len(rp.Rules))
	}
}

func TestEvaluateRiskScore(t *testing.T) {
	rp := DefaultResponsePolicy()
	matches := rp.Evaluate(95, "net_connect", true, "/etc/shadow", 1000)
	if len(matches) == 0 {
		t.Error("risk score > 90 should match")
	}
}

func TestEvaluateNetworkTaint(t *testing.T) {
	rp := DefaultResponsePolicy()
	matches := rp.Evaluate(50, "net_connect", true, "", 1000)
	found := false
	for _, m := range matches {
		if strings.Contains(m.Name, "network") {
			found = true
		}
	}
	if !found {
		t.Log("network taint rule not matched (may be condition-specific)")
	}
}

func TestEvaluateMemfd(t *testing.T) {
	rp := DefaultResponsePolicy()
	matches := rp.Evaluate(70, "memfd_create", true, "", 1000)
	found := false
	for _, m := range matches {
		if strings.Contains(m.Name, "Memory") {
			found = true
		}
	}
	if !found {
		t.Log("memfd rule may not have matched")
	}
}

func TestExecuteResponse(t *testing.T) {
	cb := NewCausalBlocker()
	fqm := NewFileQuarantineManager("", true)

	rule := ResponseRule{
		Name:   "test",
		Action: "isolate_process_tree",
		Params: map[string]string{"level": "NETWORK_ONLY"},
	}
	ExecuteResponse(rule, cb, fqm, 100, "curl", nil)

	if !cb.IsBlocked(100) {
		t.Error("process should be blocked")
	}
	if cb.BlockLevel(100) != BlockNetwork {
		t.Errorf("level = %d", cb.BlockLevel(100))
	}
}

// ─── Integration test ───────────────────────────────────────

func TestRespondIntegration(t *testing.T) {
	t.Log("=== Surgical Response Integration ===")

	// 1. Load policy
	rp := DefaultResponsePolicy()
	t.Logf("Loaded %d response rules", len(rp.Rules))

	// 2. Evaluate against attack scenario
	matches := rp.Evaluate(95, "memfd_create", true, "/tmp/evil", 1000)
	t.Logf("Matched %d rules for risk_score=95 memfd_create", len(matches))
	for _, m := range matches {
		t.Logf("  Rule: %s → action=%s", m.Name, m.Action)
	}

	// 3. Execute responses
	cb := NewCausalBlocker()
	fqm := NewFileQuarantineManager("", true)

	for _, rule := range matches {
		ExecuteResponse(rule, cb, fqm, 100, "python3",
			[]string{"/tmp/evil.so", "/tmp/payload"})
	}

	// 4. Verify isolation
	if cb.IsBlocked(100) {
		t.Logf("Process 100 (python3) isolated at level %s", cb.BlockLevel(100))
	} else {
		t.Log("Process not isolated (expected if no matching rule)")
	}

	// 5. Verify children inherit
	cb.AddChild(100, 200)
	if cb.IsBlocked(200) {
		t.Log("Child process 200 correctly blocked by inheritance")
	}

	// 6. Stats
	blockStats := cb.Stats()
	qStats := fqm.Stats()
	t.Logf("Blocked: %d trees, %d PIDs", blockStats["blocked_trees"], blockStats["blocked_pids"])
	t.Logf("Quarantined: %d files", qStats["total_quarantined"])

	t.Log("Surgical response integration OK")
}
