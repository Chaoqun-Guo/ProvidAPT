// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package releasecheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunReportsCommercialWarnings(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	evidencePath := filepath.Join(dir, "release-evidence.md")

	cfg := []byte(`
output:
  dir: /tmp/providapt
api:
  cors_origins: ["https://soc.example.com"]
storage:
  encrypt: true
  key_file: /etc/providapt/key
support_bundle:
  retain_archives: 5
license:
  path: /etc/providapt/license.json
`)
	if err := os.WriteFile(cfgPath, cfg, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, []byte("| status | _pending_ |\n"), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:   cfgPath,
		EvidencePath: evidencePath,
		Version:      "dev",
		Commit:       "none",
		BuildDate:    "unknown",
	})

	if report.HasFailures() {
		t.Fatalf("unexpected failures: %+v", report.Checks)
	}
	if report.Warnings == 0 {
		t.Fatalf("expected commercial warnings: %+v", report.Checks)
	}
	if report.CommercialReady {
		t.Fatal("expected commercial_ready=false with warnings")
	}
	if !report.ReleaseReady {
		t.Fatal("expected release_ready=true without failures")
	}
}

func TestRunFailsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(cfgPath, []byte("output:\n  format: xml\n"), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath: cfgPath,
		Version:    "1.2.2",
		Commit:     "abcdef0",
		BuildDate:  "2026-07-08T00:00:00Z",
	})

	if !report.HasFailures() {
		t.Fatalf("expected invalid config failure: %+v", report.Checks)
	}
	if report.ReleaseReady {
		t.Fatal("expected release_ready=false")
	}
}

func TestRunCommercialReady(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	evidencePath := filepath.Join(dir, "release-evidence.md")

	cfg := []byte(`
output:
  dir: /tmp/providapt
api:
  auth_enabled: true
  cors_origins: ["https://soc.example.com"]
storage:
  encrypt: true
  key_file: /etc/providapt/key
support_bundle:
  redact_archives: true
  retain_archives: 5
license:
  path: /etc/providapt/license.json
`)
	if err := os.WriteFile(cfgPath, cfg, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, []byte("| status | pass |\n"), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:   cfgPath,
		EvidencePath: evidencePath,
		Version:      "1.2.2",
		Commit:       "abcdef0",
		BuildDate:    "2026-07-08T00:00:00Z",
	})

	if !report.CommercialReady {
		t.Fatalf("expected commercial ready: %+v", report)
	}
	if report.Summary() == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestRunAppliesWarningWaivers(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	waiverPath := filepath.Join(dir, "release-waivers.json")

	cfg := []byte(`
output:
  dir: /tmp/providapt
storage:
  encrypt: true
  key_file: /etc/providapt/key
license:
  path: /etc/providapt/license.json
`)
	if err := os.WriteFile(cfgPath, cfg, 0644); err != nil {
		t.Fatal(err)
	}
	waivers := []byte(`{
  "waivers": [
    {
      "check": "api_auth",
      "reason": "isolated customer acceptance environment",
      "approved_by": "release-manager",
      "expires": "2099-12-31"
    },
    {
      "check": "cors_origins",
      "reason": "isolated browserless acceptance environment",
      "approved_by": "release-manager"
    }
  ]
}`)
	if err := os.WriteFile(waiverPath, waivers, 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath: cfgPath,
		WaiverPath: waiverPath,
		Version:    "1.2.2",
		Commit:     "abcdef0",
		BuildDate:  "2026-07-08T00:00:00Z",
	})

	if report.Waived != 2 {
		t.Fatalf("waived = %d, want 2: %+v", report.Waived, report.Checks)
	}
	if findCheck(t, report, "api_auth").Status != StatusWaived {
		t.Fatalf("expected api_auth to be waived: %+v", report.Checks)
	}
	if findCheck(t, report, "cors_origins").Status != StatusWaived {
		t.Fatalf("expected cors_origins to be waived: %+v", report.Checks)
	}
	if report.HasFailures() {
		t.Fatalf("unexpected failures: %+v", report.Checks)
	}
	if !report.CommercialReady {
		t.Fatalf("expected commercial ready with accepted warnings: %+v", report)
	}
}

func TestRunFailsExpiredWaiver(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	waiverPath := filepath.Join(dir, "release-waivers.json")

	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(waiverPath, []byte(`{"waivers":[{"check":"api_auth","reason":"demo","approved_by":"release-manager","expires":"2000-01-01"}]}`), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath: cfgPath,
		WaiverPath: waiverPath,
		Version:    "1.2.2",
		Commit:     "abcdef0",
		BuildDate:  "2026-07-08T00:00:00Z",
	})

	if !report.HasFailures() {
		t.Fatalf("expected expired waiver failure: %+v", report.Checks)
	}
}

func TestRunValidatesChecksums(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	checksumsPath := filepath.Join(dir, "checksums.txt")

	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("a", 64) + "  providapt_linux_amd64.tar.gz\n"
	if err := os.WriteFile(checksumsPath, []byte(line), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:    cfgPath,
		ChecksumsPath: checksumsPath,
		Version:       "1.2.2",
		Commit:        "abcdef0",
		BuildDate:     "2026-07-08T00:00:00Z",
	})

	if findCheck(t, report, "release_checksums").Status != StatusPass {
		t.Fatalf("expected checksums pass: %+v", report.Checks)
	}
	if report.HasFailures() {
		t.Fatalf("unexpected failures: %+v", report.Checks)
	}
}

func TestRunFailsMalformedChecksums(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	checksumsPath := filepath.Join(dir, "checksums.txt")

	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checksumsPath, []byte("not-a-sha providapt.tar.gz\n"), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:    cfgPath,
		ChecksumsPath: checksumsPath,
		Version:       "1.2.2",
		Commit:        "abcdef0",
		BuildDate:     "2026-07-08T00:00:00Z",
	})

	if !report.HasFailures() {
		t.Fatalf("expected malformed checksums failure: %+v", report.Checks)
	}
	if findCheck(t, report, "release_checksums").Status != StatusFail {
		t.Fatalf("expected checksums fail: %+v", report.Checks)
	}
}

func TestRunValidatesChecksumsSignature(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	signaturePath := filepath.Join(dir, "checksums.txt.sig")

	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, []byte("detached signature"), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:             cfgPath,
		ChecksumsSignaturePath: signaturePath,
		Version:                "1.2.2",
		Commit:                 "abcdef0",
		BuildDate:              "2026-07-08T00:00:00Z",
	})

	if findCheck(t, report, "release_checksums_signature").Status != StatusPass {
		t.Fatalf("expected checksums signature pass: %+v", report.Checks)
	}
	if report.HasFailures() {
		t.Fatalf("unexpected failures: %+v", report.Checks)
	}
}

func TestRunFailsEmptyChecksumsSignature(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	signaturePath := filepath.Join(dir, "checksums.txt.sig")

	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, nil, 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:             cfgPath,
		ChecksumsSignaturePath: signaturePath,
		Version:                "1.2.2",
		Commit:                 "abcdef0",
		BuildDate:              "2026-07-08T00:00:00Z",
	})

	if !report.HasFailures() {
		t.Fatalf("expected empty signature failure: %+v", report.Checks)
	}
	if findCheck(t, report, "release_checksums_signature").Status != StatusFail {
		t.Fatalf("expected checksums signature fail: %+v", report.Checks)
	}
}

func TestRunValidatesSBOMs(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	spdxPath := filepath.Join(dir, "sbom.spdx.json")
	cdxPath := filepath.Join(dir, "sbom.cdx.json")

	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spdxPath, []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"providapt"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cdxPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"providapt"}]}`), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath: cfgPath,
		SBOMPaths:  []string{spdxPath, cdxPath},
		Version:    "1.2.2",
		Commit:     "abcdef0",
		BuildDate:  "2026-07-08T00:00:00Z",
	})

	matches := 0
	for _, check := range report.Checks {
		if check.Name == "release_sbom" && check.Status == StatusPass {
			matches++
		}
	}
	if matches != 2 {
		t.Fatalf("release_sbom pass count = %d, want 2: %+v", matches, report.Checks)
	}
	if report.HasFailures() {
		t.Fatalf("unexpected failures: %+v", report.Checks)
	}
}

func TestRunFailsUnrecognizedSBOM(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	sbomPath := filepath.Join(dir, "sbom.json")

	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbomPath, []byte(`{"name":"not an sbom"}`), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath: cfgPath,
		SBOMPaths:  []string{sbomPath},
		Version:    "1.2.2",
		Commit:     "abcdef0",
		BuildDate:  "2026-07-08T00:00:00Z",
	})

	if !report.HasFailures() {
		t.Fatalf("expected unrecognized SBOM failure: %+v", report.Checks)
	}
	if findCheck(t, report, "release_sbom").Status != StatusFail {
		t.Fatalf("expected SBOM fail: %+v", report.Checks)
	}
}

func findCheck(t *testing.T, report Report, name string) Check {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("check %q not found: %+v", name, report.Checks)
	return Check{}
}
