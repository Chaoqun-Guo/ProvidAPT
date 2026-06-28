// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sanity

import (
	"os"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

func TestRunChecksBasic(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Output.Dir, _ = os.MkdirTemp("", "providapt-sanity-test-*")
	defer os.RemoveAll(cfg.Output.Dir)

	report := RunChecks(cfg, nil)

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if len(report.Results) != 9 {
		t.Errorf("expected 9 checks, got %d", len(report.Results))
	}

	// Each result should have a name and status
	for _, r := range report.Results {
		if r.Name == "" {
			t.Error("check result missing Name")
		}
		if r.Status.String() == "" {
			t.Errorf("check %s: unexpected status", r.Name)
		}
		if r.Message == "" {
			t.Errorf("check %s: missing Message", r.Name)
		}
		// Fix suggestion should be present for FAIL status
		if r.Status == FAIL && r.FixSuggestion == "" {
			t.Errorf("check %s: FAIL but no FixSuggestion", r.Name)
		}
	}

	t.Logf("Report: %s", report.Summary())
}

func TestSkipList(t *testing.T) {
	cfg := config.DefaultConfig()

	report := RunChecks(cfg, []string{"bpf_lsm", "no_conflicting_ebpf"})

	for _, r := range report.Results {
		if r.Name == "bpf_lsm" || r.Name == "no_conflicting_ebpf" {
			if r.Status != WARN || r.Message != "skipped by user request" {
				t.Errorf("check %s should be skipped, got %v", r.Name, r.Status)
			}
		}
	}
}

func TestCheckKernelVersion(t *testing.T) {
	result := checkKernelVersion()
	if result.Status == FAIL && result.FixSuggestion == "" {
		t.Error("FAIL without FixSuggestion")
	}
	t.Logf("kernel: %s", result.Message)
}

func TestEvaluateKernelVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		status  Status
	}{
		{name: "full support", version: "6.8.0-124-generic", status: PASS},
		{name: "recommended floor", version: "5.11.0", status: PASS},
		{name: "compatibility mode on centos8", version: "4.18.0-348.el8.x86_64", status: WARN},
		{name: "compatibility mode on 5.10", version: "5.10.0", status: WARN},
		{name: "unsupported old kernel", version: "4.14.302", status: FAIL},
		{name: "invalid format", version: "garbled", status: FAIL},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := evaluateKernelVersion(tc.version)
			if result.Status != tc.status {
				t.Fatalf("version %q: got %v, want %v", tc.version, result.Status, tc.status)
			}
			if tc.status != PASS && result.FixSuggestion == "" {
				t.Fatalf("version %q: expected fix suggestion", tc.version)
			}
		})
	}
}

func TestCheckBTF(t *testing.T) {
	result := checkBTF()
	// BTF may or may not be available in test env, but should always have a suggestion
	if result.Status == FAIL && result.FixSuggestion == "" {
		t.Error("FAIL without FixSuggestion")
	}
	t.Logf("btf: %s", result.Message)
}

func TestCheckDataDir(t *testing.T) {
	cfg := config.DefaultConfig()

	// Test with writable temp dir
	tmpDir, err := os.MkdirTemp("", "providapt-sanity-datadir-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg.Output.Dir = tmpDir
	result := checkDataDir(cfg)
	if result.Status != PASS {
		t.Errorf("expected PASS for writable dir, got %v: %s", result.Status, result.Message)
	}

	// Test with non-existent dir in unwritable location
	cfg.Output.Dir = t.TempDir() + "/nonexistent-test"
	result = checkDataDir(cfg)
	if result.Status != FAIL {
		t.Logf("non-writable dir result: %v - %s", result.Status, result.Message)
	}
	if result.Status == FAIL && result.FixSuggestion == "" {
		t.Error("FAIL without FixSuggestion")
	}
}

func TestCheckProvidaptUser(t *testing.T) {
	result := checkProvidaptUser()
	// User may or may not exist in test env
	if result.Name != "providapt_user" {
		t.Error("wrong check name")
	}
	if result.Status == FAIL && result.FixSuggestion == "" {
		t.Error("FAIL without FixSuggestion")
	}
	t.Logf("providapt user: %s", result.Message)
}

func TestCheckPIDFile(t *testing.T) {
	result := checkPIDFile()
	// PID file should not exist in test env
	if result.Name != "pidfile_stale" {
		t.Error("wrong check name")
	}
	t.Logf("pidfile: %s", result.Message)
}

func TestReportSummary(t *testing.T) {
	cfg := config.DefaultConfig()
	report := RunChecks(cfg, nil)

	summary := report.Summary()
	if summary == "" {
		t.Error("empty summary")
	}

	hasFailures := report.HasFailures()
	total := report.Passed + report.Failed + report.Warnings
	if total != len(report.Results) {
		t.Errorf("total %d != results %d", total, len(report.Results))
	}
	t.Logf("Summary: %s, HasFailures: %v", summary, hasFailures)
}
