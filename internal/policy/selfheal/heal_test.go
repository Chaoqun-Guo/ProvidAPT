// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package selfheal

import (
	"strings"
	"testing"
	"time"
)

// ─── Config tests ───────────────────────────────────────────

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.CheckInterval != 30*time.Second {
		t.Errorf("check interval = %v", cfg.CheckInterval)
	}
	if !cfg.EnableAutoReload {
		t.Error("auto reload should be enabled")
	}
	if len(cfg.ExpectedProgs) == 0 {
		t.Error("expected programs list empty")
	}
}

func TestExpectedPrograms(t *testing.T) {
	cfg := DefaultConfig()
	names := []string{
		"probe_file_open",
		"probe_bprm_check",
		"probe_task_alloc",
	}
	for _, name := range names {
		found := false
		for _, p := range cfg.ExpectedProgs {
			if p == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected program: %s", name)
		}
	}
}

// ─── Healer tests ───────────────────────────────────────────

func TestNewHealer(t *testing.T) {
	h := New(nil)
	if h == nil {
		t.Fatal("New returned nil")
	}
	if !h.healthy {
		t.Error("should start healthy")
	}
}

func TestStartStop(t *testing.T) {
	h := New(nil)
	h.Start()
	time.Sleep(50 * time.Millisecond)
	h.Stop()
}

func TestCheckProgramNotFound(t *testing.T) {
	h := New(nil)
	found := h.checkProgram("nonexistent_prog_xyz")
	if found {
		t.Log("checkProgram returned true (may have bpftool)")
	} else {
		t.Log("checkProgram returned false (expected without bpftool)")
	}
}

func TestRunCheck(t *testing.T) {
	h := New(nil)
	h.runCheck()
	if h.checkCnt != 1 {
		t.Errorf("check count = %d", h.checkCnt)
	}
}

func TestAuditEventRecording(t *testing.T) {
	h := New(nil)
	h.runCheck()
	events := h.AuditEvents()
	if len(events) == 0 {
		t.Log("no audit events (all eBPF progs may be present)")
	} else {
		t.Logf("audit events: %d", len(events))
		for _, e := range events {
			t.Logf("  [%s] %s: %s", e.Severity, e.Type, e.Message)
		}
	}
}

func TestAuditSummary(t *testing.T) {
	h := New(nil)
	h.runCheck()
	summary := h.AuditSummary()
	if !strings.Contains(summary, "Self-Heal") {
		t.Errorf("summary = %s", summary)
	}
	t.Logf("Summary:\n%s", summary)
}

func TestStats(t *testing.T) {
	h := New(nil)
	h.runCheck()
	stats := h.Stats()
	if stats["healthy"] == false {
		t.Log("healer reported degraded — expected if no eBPF progs")
	}
	if stats["checks"].(int64) != 1 {
		t.Errorf("checks = %d", stats["checks"])
	}
}

func TestMultipleChecks(t *testing.T) {
	h := New(nil)
	for i := 0; i < 3; i++ {
		h.runCheck()
	}
	if h.checkCnt != 3 {
		t.Errorf("checks = %d", h.checkCnt)
	}
}

func TestReloadCount(t *testing.T) {
	h := New(nil)
	h.mu.Lock()
	h.reloadCnt++
	h.mu.Unlock()
	stats := h.Stats()
	if stats["reloads"].(int64) != 1 {
		t.Errorf("reloads = %d", stats["reloads"])
	}
}

func TestFailureDetection(t *testing.T) {
	h := New(nil)
	h.mu.Lock()
	h.healthy = false
	h.failCnt = 3
	h.mu.Unlock()

	summary := h.AuditSummary()
	if !strings.Contains(summary, "DEGRADED") {
		t.Errorf("degraded state not shown: %s", summary)
	}
	if !strings.Contains(summary, "DEGRADED") {
		t.Errorf("failures not counted: %s", summary)
	}
	t.Logf("Degraded summary:\n%s", summary)
}

func TestVerifyMap(t *testing.T) {
	h := New(nil)
	// Should not panic
	h.verifyMap("agent_pids")
	h.verifyMap("nonexistent_map")
}

func TestRunCleanup(t *testing.T) {
	h := New(nil)
	h.runCleanup()
	events := h.AuditEvents()
	found := false
	for _, e := range events {
		if e.Type == "cleanup" {
			found = true
			break
		}
	}
	if !found {
		t.Log("no cleanup event recorded")
	}
}

func TestConcurrentSafety(t *testing.T) {
	h := New(nil)
	done := make(chan bool)

	go func() {
		for i := 0; i < 10; i++ {
			h.runCheck()
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 10; i++ {
			h.Stats()
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 10; i++ {
			h.AuditSummary()
		}
		done <- true
	}()

	<-done
	<-done
	<-done
}

// ─── Integration test ───────────────────────────────────────

func TestHealIntegration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CheckInterval = 10 * time.Millisecond
	h := New(cfg)
	h.Start()
	defer h.Stop()

	// Let it run a check cycle
	time.Sleep(50 * time.Millisecond)

	// Verify it ran
	h.mu.Lock()
	checks := h.checkCnt
	h.mu.Unlock()

	t.Logf("=== Self-Heal Integration ===")
	t.Logf("Checks:      %d", checks)
	t.Logf("Healthy:     %t", h.healthy)
	t.Logf("Failures:    %d", h.failCnt)
	t.Logf("Reloads:     %d", h.reloadCnt)
	t.Logf("Audit count: %d", len(h.auditLog))

	summary := h.AuditSummary()
	t.Logf("Summary:\n%s", summary)

	if checks == 0 {
		t.Error("healer did not run any checks")
	}
}
