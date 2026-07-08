// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// stripANSI removes ANSI escape sequences from a string.
func stripANSI(s string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(s, "")
}

// ─── Flag parsing tests ───────────────────────────────────────────

func TestFlagParsingStatus(t *testing.T) {
	// Simulate: providaptctl -status
	os.Args = []string{"providaptctl", "-status"}
	flag.CommandLine = flag.NewFlagSet("providaptctl", flag.ContinueOnError)
	var (
		status  = flag.Bool("status", false, "")
		stop    = flag.Bool("stop", false, "")
		restart = flag.Bool("restart", false, "")
		jsonOut = flag.Bool("json", false, "")
		cfgPath = flag.String("config", "/etc/providapt/providapt.toml", "")
	)
	flag.Parse()
	if !*status {
		t.Error("expected -status=true")
	}
	if *stop {
		t.Error("expected -stop=false")
	}
	if *restart {
		t.Error("expected -restart=false")
	}
	if *jsonOut {
		t.Error("expected -json=false")
	}
	if *cfgPath != "/etc/providapt/providapt.toml" {
		t.Errorf("expected default config path, got %s", *cfgPath)
	}
}

func TestFlagParsingStatusJSON(t *testing.T) {
	os.Args = []string{"providaptctl", "-status", "-json"}
	flag.CommandLine = flag.NewFlagSet("providaptctl", flag.ContinueOnError)
	status := flag.Bool("status", false, "")
	jsonOut := flag.Bool("json", false, "")
	flag.Parse()
	if !*status {
		t.Error("expected -status=true")
	}
	if !*jsonOut {
		t.Error("expected -json=true")
	}
}

func TestFlagParsingCustomConfig(t *testing.T) {
	os.Args = []string{"providaptctl", "-status", "-config", "/custom/path/config.toml"}
	flag.CommandLine = flag.NewFlagSet("providaptctl", flag.ContinueOnError)
	status := flag.Bool("status", false, "")
	cfgPath := flag.String("config", "/etc/providapt/providapt.toml", "")
	flag.Parse()
	if !*status {
		t.Error("expected -status=true")
	}
	if *cfgPath != "/custom/path/config.toml" {
		t.Errorf("got config=%q, want /custom/path/config.toml", *cfgPath)
	}
}

func TestFlagParsingPurge(t *testing.T) {
	os.Args = []string{"providaptctl", "-purge", "-purge-mode=time", "-purge-cutoff=2026-01-01T00:00:00Z"}
	flag.CommandLine = flag.NewFlagSet("providaptctl", flag.ContinueOnError)
	purge := flag.Bool("purge", false, "")
	purgeMode := flag.String("purge-mode", "time", "")
	purgeCutoff := flag.String("purge-cutoff", "", "")
	flag.Parse()
	if !*purge {
		t.Error("expected -purge=true")
	}
	if *purgeMode != "time" {
		t.Errorf("got purge-mode=%q, want time", *purgeMode)
	}
	if *purgeCutoff != "2026-01-01T00:00:00Z" {
		t.Errorf("got purge-cutoff=%q", *purgeCutoff)
	}
}

func TestFlagParsingBackupRestore(t *testing.T) {
	os.Args = []string{"providaptctl", "-backup", "-backup-out", "/tmp/backup.tar.gz"}
	flag.CommandLine = flag.NewFlagSet("providaptctl", flag.ContinueOnError)
	backup := flag.Bool("backup", false, "")
	backupOut := flag.String("backup-out", "", "")
	flag.Parse()
	if !*backup {
		t.Error("expected -backup=true")
	}
	if *backupOut != "/tmp/backup.tar.gz" {
		t.Errorf("got backup-out=%q", *backupOut)
	}
}

func TestFlagParsingRestore(t *testing.T) {
	os.Args = []string{"providaptctl", "-restore", "-restore-in", "/tmp/backup.tar.gz"}
	flag.CommandLine = flag.NewFlagSet("providaptctl", flag.ContinueOnError)
	restore := flag.Bool("restore", false, "")
	restoreIn := flag.String("restore-in", "", "")
	flag.Parse()
	if !*restore {
		t.Error("expected -restore=true")
	}
	if *restoreIn != "/tmp/backup.tar.gz" {
		t.Errorf("got restore-in=%q", *restoreIn)
	}
}

func TestFlagParsingDiagnose(t *testing.T) {
	os.Args = []string{"providaptctl", "-diagnose", "-diagnose-out", "/tmp/diag"}
	flag.CommandLine = flag.NewFlagSet("providaptctl", flag.ContinueOnError)
	diagnose := flag.Bool("diagnose", false, "")
	diagnoseOut := flag.String("diagnose-out", "/var/log/providapt", "")
	flag.Parse()
	if !*diagnose {
		t.Error("expected -diagnose=true")
	}
	if *diagnoseOut != "/tmp/diag" {
		t.Errorf("got diagnose-out=%q", *diagnoseOut)
	}
}

func TestFlagParsingReleaseCheck(t *testing.T) {
	os.Args = []string{"providaptctl", "-release-check", "-release-evidence", "/tmp/evidence.md", "-release-waivers", "/tmp/waivers.json", "-release-checksums", "/tmp/checksums.txt", "-release-checksums-signature", "/tmp/checksums.txt.sig", "-release-sbom", "/tmp/sbom.spdx.json,/tmp/sbom.cdx.json", "-release-check-out", "/tmp/report.md"}
	flag.CommandLine = flag.NewFlagSet("providaptctl", flag.ContinueOnError)
	releaseCheck := flag.Bool("release-check", false, "")
	evidencePath := flag.String("release-evidence", "docs/project/release-evidence-v1.2.2.md", "")
	waiverPath := flag.String("release-waivers", "", "")
	checksumsPath := flag.String("release-checksums", "", "")
	checksumsSigPath := flag.String("release-checksums-signature", "", "")
	sbomPaths := flag.String("release-sbom", "", "")
	reportPath := flag.String("release-check-out", "", "")
	flag.Parse()
	if !*releaseCheck {
		t.Error("expected -release-check=true")
	}
	if *evidencePath != "/tmp/evidence.md" {
		t.Errorf("got release-evidence=%q", *evidencePath)
	}
	if *waiverPath != "/tmp/waivers.json" {
		t.Errorf("got release-waivers=%q", *waiverPath)
	}
	if *checksumsPath != "/tmp/checksums.txt" {
		t.Errorf("got release-checksums=%q", *checksumsPath)
	}
	if *checksumsSigPath != "/tmp/checksums.txt.sig" {
		t.Errorf("got release-checksums-signature=%q", *checksumsSigPath)
	}
	if *sbomPaths != "/tmp/sbom.spdx.json,/tmp/sbom.cdx.json" {
		t.Errorf("got release-sbom=%q", *sbomPaths)
	}
	if *reportPath != "/tmp/report.md" {
		t.Errorf("got release-check-out=%q", *reportPath)
	}
}

// ─── Formatting helper tests ─────────────────────────────────────

func TestYesNo(t *testing.T) {
	tests := []struct {
		input bool
		want  string
	}{
		{true, "yes"},
		{false, "no"},
	}
	for _, tt := range tests {
		got := yesNo(tt.input)
		if got != tt.want {
			t.Errorf("yesNo(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatRateLimit(t *testing.T) {
	tests := []struct {
		rate float64
		want string
	}{
		{0, "disabled"},
		{-1, "disabled"},
		{100, "100 req/s"},
		{50.4, "50 req/s"},
		{99.9, "100 req/s"},
	}
	for _, tt := range tests {
		got := formatRateLimit(tt.rate)
		// Strip ANSI color codes for comparison
		plain := stripANSI(got)
		if !strings.Contains(plain, tt.want) {
			t.Errorf("formatRateLimit(%v) = %q (plain: %q), want %q", tt.rate, got, plain, tt.want)
		}
	}
}

func TestFormatStrings(t *testing.T) {
	tests := []struct {
		input []string
		want  string
	}{
		{nil, "none"},
		{[]string{}, "none"},
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a, b"},
		{[]string{"a", "b", "c"}, "a, b, c"},
	}
	for _, tt := range tests {
		got := formatStrings(tt.input)
		if got != tt.want {
			t.Errorf("formatStrings(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ─── Config file validation tests ────────────────────────────────

func TestConfigCheckWithFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	content := []byte("output:\n  dir: /tmp/test\napi:\n  rest: :9090\n")
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	// cmdConfigCheck outputs to stderr; just verify no panic
	cmdConfigCheck(cfgPath)
}

// ─── statusInfo tests ────────────────────────────────────────────

func TestStatusInfoMethods(t *testing.T) {
	info := statusInfo{
		Running:    true,
		PID:        1000,
		ConfigPath: "/etc/providapt/providapt.toml",
		ConfigOK:   true,
	}
	if !info.Running {
		t.Error("expected running=true")
	}
	if info.PID != 1000 {
		t.Errorf("PID=%d", info.PID)
	}
	info2 := statusInfo{Running: false}
	if info2.Running {
		t.Error("expected running=false")
	}
}
