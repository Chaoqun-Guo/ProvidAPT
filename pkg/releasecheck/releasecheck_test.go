// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package releasecheck

import (
	"crypto/sha256"
	"fmt"
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

func TestRunVerifiesArtifactHashes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	distDir := filepath.Join(dir, "dist")
	checksumsPath := filepath.Join(distDir, "checksums.txt")
	artifactName := "providapt_linux_amd64.tar.gz"
	artifactData := []byte("release artifact")

	if err := os.MkdirAll(distDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, artifactName), artifactData, 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(artifactData)
	line := fmt.Sprintf("%x  %s\n", sum, artifactName)
	if err := os.WriteFile(checksumsPath, []byte(line), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:    cfgPath,
		ChecksumsPath: checksumsPath,
		ArtifactsDir:  distDir,
		Version:       "1.2.2",
		Commit:        "abcdef0",
		BuildDate:     "2026-07-08T00:00:00Z",
	})

	if findCheck(t, report, "release_artifact_hashes").Status != StatusPass {
		t.Fatalf("expected artifact hashes pass: %+v", report.Checks)
	}
	if report.HasFailures() {
		t.Fatalf("unexpected failures: %+v", report.Checks)
	}
}

func TestRunValidatesRequiredArtifactMatrix(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	distDir := filepath.Join(dir, "dist")
	checksumsPath := filepath.Join(distDir, "checksums.txt")

	if err := os.MkdirAll(distDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}

	artifacts := map[string][]byte{
		"providapt_linux_amd64.tar.gz": []byte("tarball"),
		"providapt_amd64.deb":          []byte("deb"),
		"providapt_x86_64.rpm":         []byte("rpm"),
	}
	var manifest strings.Builder
	for name, data := range artifacts {
		if err := os.WriteFile(filepath.Join(distDir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&manifest, "%x  %s\n", sum, name)
	}
	if err := os.WriteFile(checksumsPath, []byte(manifest.String()), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:             cfgPath,
		ChecksumsPath:          checksumsPath,
		ArtifactsDir:           distDir,
		RequiredArtifactTypes:  []string{"archive", "deb", "rpm"},
		Version:                "1.2.2",
		Commit:                 "abcdef0",
		BuildDate:              "2026-07-08T00:00:00Z",
		ChecksumsSignaturePath: "",
	})

	if findCheck(t, report, "release_artifact_matrix").Status != StatusPass {
		t.Fatalf("expected artifact matrix pass: %+v", report.Checks)
	}
	if report.HasFailures() {
		t.Fatalf("unexpected failures: %+v", report.Checks)
	}
}

func TestRunFailsMissingRequiredArtifactType(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	distDir := filepath.Join(dir, "dist")
	checksumsPath := filepath.Join(distDir, "checksums.txt")
	artifactData := []byte("tarball")

	if err := os.MkdirAll(distDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, "providapt_linux_amd64.tar.gz"), artifactData, 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(artifactData)
	if err := os.WriteFile(checksumsPath, []byte(fmt.Sprintf("%x  providapt_linux_amd64.tar.gz\n", sum)), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:            cfgPath,
		ChecksumsPath:         checksumsPath,
		ArtifactsDir:          distDir,
		RequiredArtifactTypes: []string{"archive", "deb", "rpm"},
		Version:               "1.2.2",
		Commit:                "abcdef0",
		BuildDate:             "2026-07-08T00:00:00Z",
	})

	if !report.HasFailures() {
		t.Fatalf("expected missing artifact type failure: %+v", report.Checks)
	}
	check := findCheck(t, report, "release_artifact_matrix")
	if check.Status != StatusFail || !strings.Contains(check.Message, "deb") || !strings.Contains(check.Message, "rpm") {
		t.Fatalf("expected missing deb/rpm failure: %+v", report.Checks)
	}
}

func TestRunFailsArtifactHashMismatch(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	distDir := filepath.Join(dir, "dist")
	checksumsPath := filepath.Join(distDir, "checksums.txt")

	if err := os.MkdirAll(distDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, "providapt.tar.gz"), []byte("actual artifact"), 0644); err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("0", 64) + "  providapt.tar.gz\n"
	if err := os.WriteFile(checksumsPath, []byte(line), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:    cfgPath,
		ChecksumsPath: checksumsPath,
		ArtifactsDir:  distDir,
		Version:       "1.2.2",
		Commit:        "abcdef0",
		BuildDate:     "2026-07-08T00:00:00Z",
	})

	if !report.HasFailures() {
		t.Fatalf("expected artifact hash mismatch failure: %+v", report.Checks)
	}
	if findCheck(t, report, "release_artifact_hashes").Status != StatusFail {
		t.Fatalf("expected artifact hashes fail: %+v", report.Checks)
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

func TestRunReportsChecksumsSignatureFormat(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	signaturePath := filepath.Join(dir, "checksums.txt.sig")

	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	signature := []byte("-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n")
	if err := os.WriteFile(signaturePath, signature, 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:             cfgPath,
		ChecksumsSignaturePath: signaturePath,
		Version:                "1.2.2",
		Commit:                 "abcdef0",
		BuildDate:              "2026-07-08T00:00:00Z",
	})

	check := findCheck(t, report, "release_checksums_signature")
	if check.Status != StatusPass {
		t.Fatalf("expected checksums signature pass: %+v", report.Checks)
	}
	if !strings.Contains(check.Message, "format: gpg-armored") {
		t.Fatalf("expected gpg-armored format in message: %q", check.Message)
	}
}

func TestClassifySignatureFormat(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "gpg armored", data: []byte("-----BEGIN PGP SIGNATURE-----\nabc\n"), want: "gpg-armored"},
		{name: "minisign", data: []byte("untrusted comment: signature\nabc\ntrusted comment: timestamp\nsig\n"), want: "minisign"},
		{name: "cosign bundle", data: []byte(`{"mediaType":"application/vnd.dev.cosign.bundle.v0.3+json","verificationMaterial":{}}`), want: "cosign-bundle"},
		{name: "unknown binary", data: []byte{0x00, 0x01, 0x02}, want: "unknown-or-binary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySignatureFormat(tt.data); got != tt.want {
				t.Fatalf("classifySignatureFormat() = %q, want %q", got, tt.want)
			}
		})
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
