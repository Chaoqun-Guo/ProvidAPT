// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package releasecheck

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunReportsReleaseWarnings(t *testing.T) {
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
		t.Fatalf("expected release warnings: %+v", report.Checks)
	}
	if report.StrictReleaseReady {
		t.Fatal("expected strict_release_ready=false with warnings")
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

func TestRunStrictReleaseReady(t *testing.T) {
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
`)
	if err := os.WriteFile(cfgPath, cfg, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, []byte("Release: 1.2.2\nCommit SHA: abcdef0\n| status | pass |\n"), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:   cfgPath,
		EvidencePath: evidencePath,
		Version:      "1.2.2",
		Commit:       "abcdef0",
		BuildDate:    "2026-07-08T00:00:00Z",
	})

	if !report.StrictReleaseReady {
		t.Fatalf("expected release signoff ready: %+v", report)
	}
	if report.Summary() == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestRunWarnsOnStaleReleaseEvidenceCommit(t *testing.T) {
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
`)
	if err := os.WriteFile(cfgPath, cfg, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, []byte("Release: 1.2.2\nCommit SHA: old1234\n| status | pass |\n"), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:   cfgPath,
		EvidencePath: evidencePath,
		Version:      "1.2.2",
		Commit:       "abcdef0",
		BuildDate:    "2026-07-08T00:00:00Z",
	})

	check := findCheck(t, report, "release_evidence")
	if check.Status != StatusWarn || !strings.Contains(check.Message, "abcdef0") {
		t.Fatalf("expected stale evidence warning: %+v", check)
	}
	if report.StrictReleaseReady {
		t.Fatal("expected strict_release_ready=false with stale release evidence")
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
	if !report.StrictReleaseReady {
		t.Fatalf("expected release signoff ready with accepted warnings: %+v", report)
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

func TestRunIgnoresExternalGateWaivers(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	waiverPath := filepath.Join(dir, "release-waivers.json")

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
`)
	if err := os.WriteFile(cfgPath, cfg, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(waiverPath, []byte(`{"waivers":[{"gate":"grype","status":"approved_with_risk","reason":"local scanner unavailable","approved_by":"security","expires":"2099-12-31"}]}`), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath: cfgPath,
		WaiverPath: waiverPath,
		Version:    "1.2.2",
		Commit:     "abcdef0",
		BuildDate:  "2026-07-08T00:00:00Z",
	})

	if report.HasFailures() || !report.StrictReleaseReady {
		t.Fatalf("expected external gate waiver to be ignored by releasecheck: %+v", report)
	}
	if report.Warnings != 0 || report.Waived != 0 {
		t.Fatalf("unexpected waiver accounting: warnings=%d waived=%d checks=%+v", report.Warnings, report.Waived, report.Checks)
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
		"providapt_linux_amd64.tar.gz":    []byte("tarball"),
		"providapt_amd64.deb":             []byte("deb"),
		"providapt_x86_64.rpm":            []byte("rpm"),
		"providapt-helm-v1.2.2.tgz":       []byte("helm"),
		"providapt-monitoring-v1.2.2.tgz": []byte("monitoring"),
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
		RequiredArtifactTypes:  []string{"archive", "deb", "rpm", "helm", "monitoring"},
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

func TestRunVerifiesProvidAPTEd25519ChecksumsSignature(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	artifactPath := filepath.Join(dir, "providapt.tar.gz")
	checksumsPath := filepath.Join(dir, "checksums.txt")
	signaturePath := filepath.Join(dir, "checksums.txt.sig")

	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("artifact"))
	checksums := fmt.Sprintf("%x  providapt.tar.gz\n", digest)
	if err := os.WriteFile(checksumsPath, []byte(checksums), 0644); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := os.ReadFile(checksumsPath)
	if err != nil {
		t.Fatal(err)
	}
	msgDigest := sha256.Sum256(msg)
	sig := fmt.Sprintf(`{"type":"providapt-ed25519-checksums-v1","algorithm":"ed25519","message_sha256":"%x","public_key":"%s","signature":"%s"}`,
		msgDigest,
		hex.EncodeToString(pub),
		base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)),
	)
	if err := os.WriteFile(signaturePath, []byte(sig), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:             cfgPath,
		ChecksumsPath:          checksumsPath,
		ChecksumsSignaturePath: signaturePath,
		ArtifactsDir:           dir,
		Version:                "1.2.2",
		Commit:                 "abcdef0",
		BuildDate:              "2026-07-08T00:00:00Z",
	})

	if report.HasFailures() {
		t.Fatalf("unexpected signature verification failure: %+v", report.Checks)
	}
	check := findCheck(t, report, "release_checksums_signature")
	if check.Status != StatusPass || !strings.Contains(check.Message, "format: providapt-ed25519") {
		t.Fatalf("expected providapt-ed25519 pass: %+v", check)
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

func TestRunWarnsOnStaleHandoffPackage(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	handoffDir := filepath.Join(dir, "handoff")
	if err := os.MkdirAll(filepath.Join(handoffDir, "docs", "project"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest := "Release: v1.2.3\nCommit SHA: abcdef0\n"
	if err := os.WriteFile(filepath.Join(handoffDir, "MANIFEST.md"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	staleApproval := "| Product | pending | pending | External owner required |\n"
	if err := os.WriteFile(filepath.Join(handoffDir, "docs", "project", "external-approval-request-v1.2.3-rc.1.md"), []byte(staleApproval), 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:  cfgPath,
		HandoffPath: handoffDir,
		Version:     "v1.2.3",
		Commit:      "abcdef0",
		BuildDate:   "2026-07-08T00:00:00Z",
	})

	check := findCheck(t, report, "release_handoff")
	if check.Status != StatusWarn || !strings.Contains(check.Message, "stale release text") {
		t.Fatalf("expected stale handoff warning: %+v", check)
	}
	if report.StrictReleaseReady {
		t.Fatal("expected strict_release_ready=false with stale handoff")
	}
}

func TestRunPassesCurrentHandoffZip(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "providapt.toml")
	handoffPath := filepath.Join(dir, "handoff.zip")
	if err := os.WriteFile(cfgPath, []byte("output:\n  dir: /tmp/providapt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	zipWriter := zip.NewWriter(file)
	writer, err := zipWriter.Create("providapt/MANIFEST.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("Version: v1.2.3\nCommit evidence: abcdef0\nExternal approvals are required.\n")); err != nil {
		t.Fatal(err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	report := Run(Options{
		ConfigPath:  cfgPath,
		HandoffPath: handoffPath,
		Version:     "v1.2.3",
		Commit:      "abcdef0",
		BuildDate:   "2026-07-08T00:00:00Z",
	})

	check := findCheck(t, report, "release_handoff")
	if check.Status != StatusPass {
		t.Fatalf("expected handoff pass: %+v", check)
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
