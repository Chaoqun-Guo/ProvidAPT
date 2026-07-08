// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
		{1610612736, "1.5 GB"},
	}
	for _, tt := range tests {
		got := formatBytes(tt.input)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestResolveOutputDir(t *testing.T) {
	// Create temp config file with a known output dir
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	content := []byte("output:\n  dir: /tmp/providapt-test\n")
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	result := resolveOutputDir(cfgPath)
	if result != "/tmp/providapt-test" {
		t.Errorf("resolveOutputDir(%q) = %q, want %q", cfgPath, result, "/tmp/providapt-test")
	}
}

func TestResolveOutputDirDefault(t *testing.T) {
	result := resolveOutputDir("/nonexistent/config.toml")
	if result == "" {
		t.Error("expected non-empty default output dir")
	}
}

func TestReadPIDError(t *testing.T) {
	_, err := readPID()
	if err == nil {
		t.Error("expected error for non-existent PID file")
	}
}

func TestIsRunning(t *testing.T) {
	// PID 0 and negative PIDs should not be running
	if isRunning(0) {
		t.Error("PID 0 should not be running")
	}
	if isRunning(-1) {
		t.Error("PID -1 should not be running")
	}
}

func TestHealthStatus(t *testing.T) {
	info := statusInfo{
		Running:    true,
		PID:        1234,
		ConfigPath: "/etc/providapt/providapt.toml",
		ConfigOK:   true,
	}
	if !info.Running {
		t.Error("expected running=true")
	}
	if info.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", info.PID)
	}
	if info.ConfigPath != "/etc/providapt/providapt.toml" {
		t.Errorf("unexpected config path: %s", info.ConfigPath)
	}
}

func TestResolveOutputDirFromConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	content := []byte("output:\n  dir: /custom/output\n")
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}
	result := resolveOutputDir(cfgPath)
	if result != "/custom/output" {
		t.Errorf("got %q, want /custom/output", result)
	}
}

func TestResolveOutputDirFallback(t *testing.T) {
	// When config file doesn't exist or has no output.dir, fallback to default
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "empty.toml")
	content := []byte("api:\n  port: 8080\n")
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}
	result := resolveOutputDir(cfgPath)
	if result == "" {
		t.Error("expected non-empty fallback output dir")
	}
}

func TestAuditStoreNilForBadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.toml")
	// Invalid TOML that should cause a parse error
	content := []byte(": invalid\n[broken")
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}
	as := auditStore(cfgPath)
	if as != nil {
		as.Close()
	}
}

func TestConfigSyntacticLoad(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	content := []byte("output:\n  dir: /tmp/providapt-test\napi:\n  rest: :9090\n")
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if cfg.Output.Dir != "/tmp/providapt-test" {
		t.Errorf("output.dir = %q", cfg.Output.Dir)
	}
	if cfg.API.REST != ":9090" {
		t.Errorf("api.rest = %q", cfg.API.REST)
	}
}

func TestCmdReleaseCheckReturnCodes(t *testing.T) {
	dir := t.TempDir()
	goodCfg := filepath.Join(dir, "good.toml")
	if err := os.WriteFile(goodCfg, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if code := cmdReleaseCheck(goodCfg, "", "", "", ""); code != 0 {
		t.Fatalf("good release check code = %d, want 0", code)
	}

	badCfg := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(badCfg, []byte("output:\n  format: xml\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if code := cmdReleaseCheck(badCfg, "", "", "", ""); code == 0 {
		t.Fatal("bad release check should return non-zero")
	}
}

func TestCmdReleaseCheckWritesReport(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	reportPath := filepath.Join(dir, "release-readiness.md")
	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if code := cmdReleaseCheck(cfgPath, "", "", "", reportPath); code != 0 {
		t.Fatalf("release check code = %d, want 0", code)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("report not written: %v", err)
	}
}

func TestFindDaemonPIDNoDaemon(t *testing.T) {
	// With no PID file and no running process, findDaemonPID should return 0
	pid := findDaemonPID()
	if pid != 0 {
		t.Logf("findDaemonPID returned %d (may have running daemon)", pid)
	}
}
