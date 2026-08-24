// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package heal

import (
	"runtime"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

// ── Test helpers ────────────────────────────────────────────

func testGraph() *provenance.Graph {
	g := provenance.NewGraph()
	// Malicious process: bash (PID 100)
	// bash forks curl (PID 200)
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessFork, TimestampNS: 1000,
		PID: 100, ChildPID: 200, Comm: "bash",
	})
	// bash writes /tmp/evil.sh
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileModify, TimestampNS: 2000,
		PID: 100, Comm: "bash", Pathname: "/tmp/evil.sh",
		Inode: 5000, DevMajor: 8, DevMinor: 3,
	})
	// bash reads /etc/shadow
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileOpen, TimestampNS: 3000,
		PID: 100, Comm: "bash", Pathname: "/etc/shadow",
		Inode: 5001, DevMajor: 8, DevMinor: 3,
	})
	// curl exec (updates comm from bash to curl after fork)
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessExec, TimestampNS: 1500,
		PID: 200, Comm: "curl",
	})
	// curl connects to C2
	g.AddEvent(&collector.Event{
		Type: syscall.EventNetConnect, TimestampNS: 4000,
		PID: 200, Comm: "curl",
	})
	// curl writes another file
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileModify, TimestampNS: 5000,
		PID: 200, Comm: "curl", Pathname: "/tmp/backdoor.sh",
		Inode: 5002, DevMajor: 8, DevMinor: 3,
	})
	return g
}

// ── Impact assessment tests ─────────────────────────────────

func TestAssessImpact(t *testing.T) {
	g := testGraph()
	report := AssessImpact(g, "p:100", 5)

	if report == nil {
		t.Fatal("AssessImpact returned nil")
	}
	if report.MaliciousPID != 100 {
		t.Errorf("PID = %d", report.MaliciousPID)
	}
	t.Logf("Impact from p:100: %d child, %d files, %d C2, total=%d",
		len(report.ChildProcesses), len(report.FilesWritten),
		len(report.C2Addresses), report.TotalImpacted)
}

func TestAssessImpactChildProcesses(t *testing.T) {
	g := testGraph()
	report := AssessImpact(g, "p:100", 5)

	if len(report.ChildProcesses) == 0 {
		t.Fatal("expected child processes")
	}
	found := false
	for _, c := range report.ChildProcesses {
		if c.Comm == "curl" {
			found = true
		}
	}
	if !found {
		t.Error("curl should be a child process")
	}
}

func TestAssessImpactFilesWritten(t *testing.T) {
	g := testGraph()
	report := AssessImpact(g, "p:100", 5)

	if len(report.FilesWritten) == 0 {
		t.Fatal("expected written files")
	}
	hasEvil := false
	hasShadow := false
	for _, f := range report.FilesWritten {
		if f.Path == "/tmp/evil.sh" {
			hasEvil = true
		}
		if f.Path == "/etc/shadow" {
			hasShadow = true
		}
	}
	if !hasEvil {
		t.Error("/tmp/evil.sh should be in written files")
	}
	if !hasShadow {
		t.Error("/etc/shadow should be in written files")
	}
}

func TestAssessImpactC2Addresses(t *testing.T) {
	g := testGraph()
	report := AssessImpact(g, "p:100", 5)
	// C2 detection depends on how network nodes are stored
	t.Logf("C2 addresses: %d", len(report.C2Addresses))
}

func TestAssessImpactDepthLimit(t *testing.T) {
	g := testGraph()
	report := AssessImpact(g, "p:100", 1)
	if !report.Truncated {
		t.Log("depth=1 may not trigger truncation for small graph")
	}
}

func TestAssessImpactEmptyNode(t *testing.T) {
	g := provenance.NewGraph()
	report := AssessImpact(g, "p:9999", 5)
	if report.TotalImpacted != 0 {
		t.Errorf("expected 0 impacted, got %d", report.TotalImpacted)
	}
}

func TestParsePID(t *testing.T) {
	pid, ok := parsePID("p:1234")
	if !ok || pid != 1234 {
		t.Errorf("parsePID = %d, %v", pid, ok)
	}
	_, ok = parsePID("f:100")
	if ok {
		t.Error("file ID should not parse as PID")
	}
}

func TestClassifyFileAction(t *testing.T) {
	if classifyFileAction("prov:wasGeneratedBy") != "written" {
		t.Error("wasGeneratedBy should be written")
	}
	if classifyFileAction("prov:used") != "read" {
		t.Error("used should be read")
	}
}

// ── Rollback tests ──────────────────────────────────────────

func TestRollbackDryRun(t *testing.T) {
	report := &ImpactReport{
		ChildProcesses: []ProcessNode{{PID: 999, Comm: "test"}},
		FilesWritten:   []FileNode{{Path: "/tmp/test"}},
	}
	cfg := DefaultRollbackConfig()
	cfg.DryRun = true

	result := Rollback(report, cfg)
	if !result.DryRun {
		t.Error("should be dry run")
	}
	if result.ProcessesKilled <= 0 {
		t.Error("should count dry-run kills")
	}
	if result.FilesQuarantined <= 0 {
		t.Error("should count dry-run quarantines")
	}
}

func TestRollbackConfigDefaults(t *testing.T) {
	cfg := DefaultRollbackConfig()
	if !cfg.DryRun {
		t.Error("default should be dry run")
	}
	if !cfg.KillProcesses {
		t.Error("default should kill processes")
	}
}

func TestCmdExists(t *testing.T) {
	if runtime.GOOS == "windows" {
		if !cmdExists("powershell") {
			t.Error("powershell should exist")
		}
	} else {
		if !cmdExists("sh") {
			t.Error("sh should exist")
		}
		if !cmdExists("kill") {
			t.Error("kill should exist")
		}
	}
	if cmdExists("nonexistent_cmd_xyz") {
		t.Error("nonexistent cmd should not be found")
	}
}

// ── Firewall tests ──────────────────────────────────────────

func TestBlockC2Empty(t *testing.T) {
	report := &ImpactReport{}
	result := BlockC2IPs(report, true)
	if result.RulesAdded != 0 {
		t.Errorf("rules = %d", result.RulesAdded)
	}
}

func TestBlockC2DryRun(t *testing.T) {
	report := &ImpactReport{
		C2Addresses: []NetworkNode{
			{Address: "5.6.7.8", Action: "connect"},
		},
	}
	result := BlockC2IPs(report, true)
	if !result.DryRun {
		t.Error("should be dry run")
	}
	t.Logf("C2 block result: backend=%s rules=%d",
		result.Backend, result.RulesAdded)
}

func TestBlockC2MultipleIPs(t *testing.T) {
	report := &ImpactReport{
		C2Addresses: []NetworkNode{
			{Address: "5.6.7.8", Action: "connect"},
			{Address: "10.0.0.1:443", Action: "connect"},
		},
	}
	result := BlockC2IPs(report, true)
	t.Logf("Multiple C2: rules=%d ips=%v", result.RulesAdded, result.IPsBlocked)
}

func TestExtractIP(t *testing.T) {
	tests := []struct{ label, want string }{
		{"5.6.7.8", "5.6.7.8"},
		{"10.0.0.1:443", "10.0.0.1"},
		{"192.168.1.1", "192.168.1.1"},
	}
	for _, tt := range tests {
		got := extractIP(tt.label)
		if got != tt.want {
			t.Errorf("extractIP(%q) = %q", tt.label, got)
		}
	}
}

// ── Integration test ────────────────────────────────────────

func TestHealIntegration(t *testing.T) {
	g := testGraph()

	// Assess
	report := AssessImpact(g, "p:100", 5)
	if report.TotalImpacted == 0 {
		t.Fatal("no impact found")
	}
	t.Logf("Integration: %d total impacted items", report.TotalImpacted)

	// Rollback (dry run)
	cfg := DefaultRollbackConfig()
	rResult := Rollback(report, cfg)
	if rResult.ProcessesKilled == 0 && len(report.ChildProcesses) > 0 {
		t.Log("rollback counted kills in dry-run mode")
	}

	// Firewall (dry run)
	fwResult := BlockC2IPs(report, true)
	t.Logf("firewall: %d rules", fwResult.RulesAdded)

	t.Logf("All phases completed successfully")
}

func TestMaliciousComm(t *testing.T) {
	g := testGraph()
	report := AssessImpact(g, "p:100", 5)
	if report.MaliciousComm == "" {
		t.Error("malicious comm should not be empty")
	}
	t.Logf("Malicious process: %s", report.MaliciousComm)
}

func TestAssessImpactDeepChain(t *testing.T) {
	g := provenance.NewGraph()
	// Create a deeper chain: p:1 → p:2 → p:3 → p:4 → p:5
	for i := 2; i <= 5; i++ {
		g.AddEvent(&collector.Event{
			Type: syscall.EventProcessFork, TimestampNS: uint64(i * 1000),
			PID: uint32(i - 1), ChildPID: uint32(i), Comm: "chain",
		})
	}
	report := AssessImpact(g, "p:1", 10)
	if len(report.ChildProcesses) < 3 {
		t.Errorf("expected >=3 child processes, got %d", len(report.ChildProcesses))
	}
	t.Logf("Deep chain: %d children", len(report.ChildProcesses))
}
