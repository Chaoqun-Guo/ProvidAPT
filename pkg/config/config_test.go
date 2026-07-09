// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if !cfg.Capture.EnableNet {
		t.Error("EnableNet should be true by default")
	}
	if !cfg.Capture.EnableFile {
		t.Error("EnableFile should be true by default")
	}
	if !cfg.Capture.EnableProc {
		t.Error("EnableProc should be true by default")
	}
	if cfg.API.GRPC != ":50051" {
		t.Errorf("gRPC addr = %q, want :50051", cfg.API.GRPC)
	}
	if cfg.Telemetry.Interval != "30s" {
		t.Errorf("telemetry interval = %q, want 30s", cfg.Telemetry.Interval)
	}
	if len(cfg.Kernel.Hooks) == 0 {
		t.Error("expected default hooks")
	}
	if cfg.SupportBundle.RetainArchives != 5 {
		t.Errorf("support retain_archives = %d, want 5", cfg.SupportBundle.RetainArchives)
	}
	if !cfg.SupportBundle.RedactArchives {
		t.Error("support redact_archives should be true by default")
	}
	if cfg.License.SigningKey != "" {
		t.Error("license signing_key should be empty by default")
	}
}

func TestLoadNonExistent(t *testing.T) {
	cfg, err := Load("/tmp/nonexistent_providapt_config.json")
	if err != nil {
		t.Fatalf("Load non-existent: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil")
	}
	// Should return defaults
	if !cfg.Capture.EnableNet {
		t.Error("should have default net enabled")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"capture":{"enable_net":false,"enable_file":true},"api":{"grpc":":9090"}}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Capture.EnableNet {
		t.Error("EnableNet should be false from config")
	}
	if !cfg.Capture.EnableFile {
		t.Error("EnableFile should be true from config")
	}
	if cfg.API.GRPC != ":9090" {
		t.Errorf("gRPC = %q", cfg.API.GRPC)
	}
}

func TestLoadInvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte(": : invalid yaml : :"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadMergesDefaults(t *testing.T) {
	// Config with partial fields should merge with defaults
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.json")
	content := `{"capture":{"enable_net":false}}`
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Should be overridden
	if cfg.Capture.EnableNet {
		t.Error("EnableNet should be false")
	}
	// Should keep default
	if !cfg.Capture.EnableFile {
		t.Error("EnableFile should keep default true")
	}
	if !cfg.Capture.EnableProc {
		t.Error("EnableProc should keep default true")
	}
}

func TestOutputDirDefault(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Output.Dir != "/var/log/providapt" {
		t.Errorf("Output.Dir = %q", cfg.Output.Dir)
	}
	if cfg.Output.Format != "json" {
		t.Errorf("Output.Format = %q", cfg.Output.Format)
	}
}

func TestKernelConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Kernel.Verbose {
		t.Error("Verbose should be false by default")
	}
	if cfg.Kernel.AttachmentMode != "auto" {
		t.Errorf("AttachmentMode = %q, want auto", cfg.Kernel.AttachmentMode)
	}
	if len(cfg.Kernel.Hooks) == 0 {
		t.Error("Hooks should not be empty")
	}
}

func TestCaptureMaxEvents(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Capture.MaxEvents != 0 {
		t.Errorf("MaxEvents = %d, want 0 (unlimited)", cfg.Capture.MaxEvents)
	}
}

func TestLoadYAML(t *testing.T) {
	yaml := `
output:
  dir: /tmp/providapt-test
  format: json
log:
  level: debug
api:
  rest: ":9090"
  grpc: ":50052"
capture:
  include_comms:
    - curl
    - ssh
`
	path := writeTempFile(t, "config.*.yaml", yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load YAML: %v", err)
	}
	if cfg.Output.Dir != "/tmp/providapt-test" {
		t.Errorf("output dir = %q", cfg.Output.Dir)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log level = %q", cfg.Log.Level)
	}
	if cfg.API.REST != ":9090" {
		t.Errorf("rest addr = %q", cfg.API.REST)
	}
	if len(cfg.Capture.IncludeComms) != 2 || cfg.Capture.IncludeComms[0] != "curl" || cfg.Capture.IncludeComms[1] != "ssh" {
		t.Errorf("include_comms = %#v, want [curl ssh]", cfg.Capture.IncludeComms)
	}
}

func TestLoadJSONViaYAML(t *testing.T) {
	json := `{
		"output": { "dir": "/tmp/json-test", "format": "json" },
		"api": { "rest": ":7070" }
	}`
	path := writeTempFile(t, "config.*.json", json)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load JSON: %v", err)
	}
	if cfg.Output.Dir != "/tmp/json-test" {
		t.Errorf("output dir = %q", cfg.Output.Dir)
	}
	if cfg.API.REST != ":7070" {
		t.Errorf("rest addr = %q", cfg.API.REST)
	}
}

func TestEnvOverrides(t *testing.T) {
	os.Setenv("PROVIDAPT_LOG_LEVEL", "error")
	os.Setenv("PROVIDAPT_OUTPUT_DIR", "/env/test")
	os.Setenv("PROVIDAPT_CAPTURE_ENABLE_NET", "false")
	os.Setenv("PROVIDAPT_CAPTURE_INCLUDE_COMMS", "curl, ssh")
	os.Setenv("PROVIDAPT_KERNEL_ATTACHMENT_MODE", "kprobe")
	os.Setenv("PROVIDAPT_TELEMETRY_ENDPOINT", "127.0.0.1:5444")
	os.Setenv("PROVIDAPT_TELEMETRY_ENABLE_TLS", "true")
	defer func() {
		os.Unsetenv("PROVIDAPT_LOG_LEVEL")
		os.Unsetenv("PROVIDAPT_OUTPUT_DIR")
		os.Unsetenv("PROVIDAPT_CAPTURE_ENABLE_NET")
		os.Unsetenv("PROVIDAPT_CAPTURE_INCLUDE_COMMS")
		os.Unsetenv("PROVIDAPT_KERNEL_ATTACHMENT_MODE")
		os.Unsetenv("PROVIDAPT_TELEMETRY_ENDPOINT")
		os.Unsetenv("PROVIDAPT_TELEMETRY_ENABLE_TLS")
	}()

	yaml := `
output:
  dir: /yaml/dir
log:
  level: debug
capture:
  enable_net: true
`
	path := writeTempFile(t, "config.*.yaml", yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Level != "error" {
		t.Errorf("env override: log level = %q, want error", cfg.Log.Level)
	}
	if cfg.Output.Dir != "/env/test" {
		t.Errorf("env override: output dir = %q, want /env/test", cfg.Output.Dir)
	}
	if cfg.Capture.EnableNet != false {
		t.Errorf("env override: enable_net = %v, want false", cfg.Capture.EnableNet)
	}
	if len(cfg.Capture.IncludeComms) != 2 || cfg.Capture.IncludeComms[0] != "curl" || cfg.Capture.IncludeComms[1] != "ssh" {
		t.Errorf("env override: include_comms = %#v, want [curl ssh]", cfg.Capture.IncludeComms)
	}
	if cfg.Kernel.AttachmentMode != "kprobe" {
		t.Errorf("env override: attachment_mode = %q, want kprobe", cfg.Kernel.AttachmentMode)
	}
	if cfg.Telemetry.Endpoint != "127.0.0.1:5444" {
		t.Errorf("env override: telemetry endpoint = %q", cfg.Telemetry.Endpoint)
	}
	if !cfg.Telemetry.EnableTLS {
		t.Error("env override: telemetry TLS should be enabled")
	}
}

func TestValidateAuthRoles(t *testing.T) {
	cfg := DefaultConfig()
	cfg.API.AuthRoles = map[string]string{"admin-key": "admin", "auditor-key": "auditor"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	cfg.API.AuthRoles["bad-key"] = "owner"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestLoadAuthIdentities(t *testing.T) {
	yaml := `
api:
  auth_enabled: true
  auth_keys:
    - admin-key
  auth_roles:
    admin-key: admin
  auth_identities:
    admin-key: SecOps On-Call
`
	path := writeTempFile(t, "config.*.yaml", yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.API.AuthIdentities["admin-key"] != "SecOps On-Call" {
		t.Fatalf("auth identity = %q", cfg.API.AuthIdentities["admin-key"])
	}
}

func TestNotifyRetryEnvOverrides(t *testing.T) {
	os.Setenv("PROVIDAPT_NOTIFY_MAX_ATTEMPTS", "5")
	os.Setenv("PROVIDAPT_NOTIFY_RETRY_BACKOFF", "2s")
	defer func() {
		os.Unsetenv("PROVIDAPT_NOTIFY_MAX_ATTEMPTS")
		os.Unsetenv("PROVIDAPT_NOTIFY_RETRY_BACKOFF")
	}()

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)

	if cfg.Notify.MaxAttempts != 5 {
		t.Fatalf("notify max attempts = %d", cfg.Notify.MaxAttempts)
	}
	if cfg.Notify.RetryBackoff != "2s" {
		t.Fatalf("notify retry backoff = %q", cfg.Notify.RetryBackoff)
	}
}

func TestNotifyServiceNowEnvOverrides(t *testing.T) {
	os.Setenv("PROVIDAPT_NOTIFY_SERVICENOW_BASE_URL", "https://snow.example.com")
	os.Setenv("PROVIDAPT_NOTIFY_SERVICENOW_USER", "svc-providapt")
	os.Setenv("PROVIDAPT_NOTIFY_SERVICENOW_PASS", "top-secret")
	os.Setenv("PROVIDAPT_NOTIFY_SERVICENOW_TABLE", "incident")
	defer func() {
		os.Unsetenv("PROVIDAPT_NOTIFY_SERVICENOW_BASE_URL")
		os.Unsetenv("PROVIDAPT_NOTIFY_SERVICENOW_USER")
		os.Unsetenv("PROVIDAPT_NOTIFY_SERVICENOW_PASS")
		os.Unsetenv("PROVIDAPT_NOTIFY_SERVICENOW_TABLE")
	}()

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)
	resolveSecrets(cfg)

	if cfg.Notify.ServiceNowBaseURL != "https://snow.example.com" {
		t.Fatalf("servicenow base url = %q", cfg.Notify.ServiceNowBaseURL)
	}
	if cfg.Notify.ServiceNowUser != "svc-providapt" {
		t.Fatalf("servicenow user = %q", cfg.Notify.ServiceNowUser)
	}
	if cfg.Notify.ServiceNowPass != "top-secret" {
		t.Fatalf("servicenow pass = %q", cfg.Notify.ServiceNowPass)
	}
	if cfg.Notify.ServiceNowTable != "incident" {
		t.Fatalf("servicenow table = %q", cfg.Notify.ServiceNowTable)
	}
}

func TestSupportBundleEnvOverrides(t *testing.T) {
	os.Setenv("PROVIDAPT_SUPPORT_RETAIN_ARCHIVES", "8")
	os.Setenv("PROVIDAPT_SUPPORT_REDACT_ARCHIVES", "false")
	defer func() {
		os.Unsetenv("PROVIDAPT_SUPPORT_RETAIN_ARCHIVES")
		os.Unsetenv("PROVIDAPT_SUPPORT_REDACT_ARCHIVES")
	}()

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)

	if cfg.SupportBundle.RetainArchives != 8 {
		t.Fatalf("support retain_archives = %d", cfg.SupportBundle.RetainArchives)
	}
	if cfg.SupportBundle.RedactArchives {
		t.Fatal("support redact_archives should be false")
	}
}

func TestLicenseAndUpgradeEnvOverrides(t *testing.T) {
	os.Setenv("PROVIDAPT_LICENSE_PATH", "/etc/providapt/license.yaml")
	os.Setenv("PROVIDAPT_LICENSE_SIGNING_KEY", "env:PROVIDAPT_LICENSE_HMAC")
	os.Setenv("PROVIDAPT_LICENSE_HMAC", "shared-secret")
	os.Setenv("PROVIDAPT_LICENSE_REVOKED_IDS", "lic-1, lic-2")
	os.Setenv("PROVIDAPT_LICENSE_GRACE_PERIOD_DAYS", "14")
	os.Setenv("PROVIDAPT_LICENSE_PUBLIC_KEY_PATH", "/etc/providapt/license.pub")
	os.Setenv("PROVIDAPT_LICENSE_REVOCATION_URL", "https://licenses.example.com/revocations.json")
	os.Setenv("PROVIDAPT_LICENSE_REVOCATION_CACHE", "/var/lib/providapt/revocations.json")
	os.Setenv("PROVIDAPT_LICENSE_REVOCATION_SIG_URL", "https://licenses.example.com/revocations.json.sig")
	os.Setenv("PROVIDAPT_LICENSE_REVOCATION_SIG_CACHE", "/var/lib/providapt/revocations.json.sig")
	os.Setenv("PROVIDAPT_UPGRADE_DOWNLOAD_URL", "https://downloads.example.com/providapt.tar.gz")
	os.Setenv("PROVIDAPT_UPGRADE_PACKAGE_PATH", "/tmp/providapt-upgrade.tar.gz")
	os.Setenv("PROVIDAPT_UPGRADE_EXPECTED_SHA256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	os.Setenv("PROVIDAPT_UPGRADE_SIGNATURE_PATH", "/tmp/providapt-upgrade.tar.gz.sig")
	os.Setenv("PROVIDAPT_UPGRADE_SIGNING_KEY", "upgrade-signing-secret")
	os.Setenv("PROVIDAPT_UPGRADE_PUBLIC_KEY_PATH", "/etc/providapt/upgrade.pub")
	os.Setenv("PROVIDAPT_UPGRADE_ROLLBACK_PLAN", "snapshot VM before rollout")
	defer func() {
		os.Unsetenv("PROVIDAPT_LICENSE_PATH")
		os.Unsetenv("PROVIDAPT_LICENSE_SIGNING_KEY")
		os.Unsetenv("PROVIDAPT_LICENSE_HMAC")
		os.Unsetenv("PROVIDAPT_LICENSE_REVOKED_IDS")
		os.Unsetenv("PROVIDAPT_LICENSE_GRACE_PERIOD_DAYS")
		os.Unsetenv("PROVIDAPT_LICENSE_PUBLIC_KEY_PATH")
		os.Unsetenv("PROVIDAPT_LICENSE_REVOCATION_URL")
		os.Unsetenv("PROVIDAPT_LICENSE_REVOCATION_CACHE")
		os.Unsetenv("PROVIDAPT_LICENSE_REVOCATION_SIG_URL")
		os.Unsetenv("PROVIDAPT_LICENSE_REVOCATION_SIG_CACHE")
		os.Unsetenv("PROVIDAPT_UPGRADE_DOWNLOAD_URL")
		os.Unsetenv("PROVIDAPT_UPGRADE_PACKAGE_PATH")
		os.Unsetenv("PROVIDAPT_UPGRADE_EXPECTED_SHA256")
		os.Unsetenv("PROVIDAPT_UPGRADE_SIGNATURE_PATH")
		os.Unsetenv("PROVIDAPT_UPGRADE_SIGNING_KEY")
		os.Unsetenv("PROVIDAPT_UPGRADE_PUBLIC_KEY_PATH")
		os.Unsetenv("PROVIDAPT_UPGRADE_ROLLBACK_PLAN")
	}()

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)
	resolveSecrets(cfg)

	if cfg.License.Path != "/etc/providapt/license.yaml" {
		t.Fatalf("license path = %q", cfg.License.Path)
	}
	if cfg.License.SigningKey != "shared-secret" {
		t.Fatalf("license signing key = %q", cfg.License.SigningKey)
	}
	if cfg.License.PublicKeyPath != "/etc/providapt/license.pub" {
		t.Fatalf("license public key path = %q", cfg.License.PublicKeyPath)
	}
	if len(cfg.License.RevokedIDs) != 2 || cfg.License.RevokedIDs[0] != "lic-1" {
		t.Fatalf("license revoked_ids = %#v", cfg.License.RevokedIDs)
	}
	if cfg.License.GracePeriodDays != 14 {
		t.Fatalf("license grace period = %d", cfg.License.GracePeriodDays)
	}
	if cfg.License.RevocationURL != "https://licenses.example.com/revocations.json" {
		t.Fatalf("license revocation_url = %q", cfg.License.RevocationURL)
	}
	if cfg.License.RevocationCache != "/var/lib/providapt/revocations.json" {
		t.Fatalf("license revocation_cache = %q", cfg.License.RevocationCache)
	}
	if cfg.License.RevocationSigURL != "https://licenses.example.com/revocations.json.sig" {
		t.Fatalf("license revocation_sig_url = %q", cfg.License.RevocationSigURL)
	}
	if cfg.License.RevocationSigCache != "/var/lib/providapt/revocations.json.sig" {
		t.Fatalf("license revocation_sig_cache = %q", cfg.License.RevocationSigCache)
	}
	if cfg.Upgrade.DownloadURL != "https://downloads.example.com/providapt.tar.gz" {
		t.Fatalf("upgrade download_url = %q", cfg.Upgrade.DownloadURL)
	}
	if cfg.Upgrade.PackagePath != "/tmp/providapt-upgrade.tar.gz" {
		t.Fatalf("upgrade package path = %q", cfg.Upgrade.PackagePath)
	}
	if cfg.Upgrade.SignaturePath != "/tmp/providapt-upgrade.tar.gz.sig" {
		t.Fatalf("upgrade signature path = %q", cfg.Upgrade.SignaturePath)
	}
	if cfg.Upgrade.SigningKey != "upgrade-signing-secret" {
		t.Fatalf("upgrade signing key = %q", cfg.Upgrade.SigningKey)
	}
	if cfg.Upgrade.PublicKeyPath != "/etc/providapt/upgrade.pub" {
		t.Fatalf("upgrade public key path = %q", cfg.Upgrade.PublicKeyPath)
	}
	if cfg.Upgrade.RollbackPlan != "snapshot VM before rollout" {
		t.Fatalf("upgrade rollback plan = %q", cfg.Upgrade.RollbackPlan)
	}
}

func TestValidateUpgradeChecksum(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upgrade.ExpectedSHA256 = "not-a-sha"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid upgrade.expected_sha256")
	}
}

func TestValidateLicenseGracePeriod(t *testing.T) {
	cfg := DefaultConfig()
	cfg.License.GracePeriodDays = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative license grace_period_days")
	}
}

func TestValidateNotifyMaxAttempts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Notify.MaxAttempts = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for notify max_attempts < 1")
	}
}

func TestValidateTicketProvider(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Notify.TicketProvider = "jira"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate jira provider: %v", err)
	}

	cfg.Notify.TicketProvider = "servicenow"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate servicenow provider: %v", err)
	}

	cfg.Notify.TicketProvider = "pagerduty"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid ticket provider")
	}
}

func TestValidateSupportBundleRetention(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SupportBundle.RetainArchives = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative support bundle retain_archives")
	}
}

func TestValidateInvalidFormat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Output.Format = "xml"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for xml format")
	}
}

func TestValidateInvalidLogLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Log.Level = "trace"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for trace log level")
	}
}

func TestValidateAttachmentMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Kernel.AttachmentMode = "kprobe"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate kprobe attachment mode: %v", err)
	}

	cfg.Kernel.AttachmentMode = "lsm"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate lsm attachment mode: %v", err)
	}

	cfg.Kernel.AttachmentMode = "definitely-not-valid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid kernel attachment mode")
	}
}

func TestValidateEncryptWithoutKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Storage.Encrypt = true
	cfg.Storage.KeyFile = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for encrypt without key_file")
	}
}

func TestAnalyzerConfig(t *testing.T) {
	yaml := `
analyzer:
  scan_interval: 60s
  deep_taint_threshold: 5
  enable_patterns:
    - pat_sensitive_exfil
    - pat_script_child
  quiet: true
`
	path := writeTempFile(t, "config.*.yaml", yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Analyzer.ScanInterval.Duration != 60e9 {
		t.Errorf("scan_interval = %d ns, want 60e9", cfg.Analyzer.ScanInterval.Duration)
	}
	if cfg.Analyzer.DeepTaintThreshold != 5 {
		t.Errorf("deep_taint_threshold = %d, want 5", cfg.Analyzer.DeepTaintThreshold)
	}
	if !cfg.Analyzer.Quiet {
		t.Error("quiet = false, want true")
	}
	if len(cfg.Analyzer.EnablePatterns) != 2 {
		t.Errorf("enable_patterns count = %d, want 2", len(cfg.Analyzer.EnablePatterns))
	}
}

func TestDurationParsing(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"30s", 30e9},
		{"5m", 300e9},
		{"1h", 3600e9},
	}
	for _, tt := range tests {
		var d Duration
		if err := d.parse(tt.input); err != nil {
			t.Errorf("parse(%q): %v", tt.input, err)
			continue
		}
		if d.Duration != tt.want {
			t.Errorf("parse(%q) = %d, want %d", tt.input, d.Duration, tt.want)
		}
	}
}

func TestTaintSecretsConfig(t *testing.T) {
	yaml := `
taint_secrets:
  untrusted_comms:
    - nginx
    - apache2
  network_tools:
    - curl
    - wget
  sensitive_paths:
    - /etc/shadow
    - /etc/passwd
`
	path := writeTempFile(t, "config.*.yaml", yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.TaintSecrets.UntrustedComms) != 2 {
		t.Errorf("untrusted_comms = %d, want 2", len(cfg.TaintSecrets.UntrustedComms))
	}
	if cfg.TaintSecrets.UntrustedComms[0] != "nginx" {
		t.Errorf("first untrusted_comm = %q, want nginx", cfg.TaintSecrets.UntrustedComms[0])
	}
}

func writeTempFile(t *testing.T, pattern, content string) string {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

// FuzzConfigLoad fuzzes config loading with arbitrary TOML content.
func FuzzConfigLoad(f *testing.F) {
	f.Add([]byte(`
output_dir = "/tmp/providapt"
[api]
http_addr = ":8080"
`))
	f.Add([]byte("invalid toml [[["))
	f.Add([]byte(""))
	f.Add([]byte("[api]\nrest = \":8080\"\n[tls]\nenable = true\ncert_file = \"/certs/cert.pem\"\nkey_file = \"/certs/key.pem\""))
	f.Add([]byte("[capture]\nmax_events = 99999\nenable_net = true\nenable_file = false\nenable_proc = true"))
	f.Add([]byte("[analyzer]\nscan_interval = \"0s\"\ndeep_taint_threshold = -1"))
	f.Add([]byte("[storage]\nencrypt = true"))
	f.Add([]byte("[kernel]\nverbose = true\nhooks = [\"file_open\", \"socket_connect\", \"nonexistent_hook\"]"))
	f.Add([]byte("\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := filepath.Join(t.TempDir(), "providapt.toml")
		if err := os.WriteFile(tmp, data, 0644); err != nil {
			return
		}
		cfg, err := Load(tmp)
		_ = cfg
		_ = err
	})
}
