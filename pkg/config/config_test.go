// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if cfg.Compliance.ApprovalTTL != "24h" || cfg.Compliance.ReportInterval != "24h" {
		t.Fatalf("commercial compliance defaults = %#v", cfg.Compliance)
	}
	if cfg.Upgrade.CanaryPercent != 10 {
		t.Fatalf("upgrade canary default = %d", cfg.Upgrade.CanaryPercent)
	}
	if cfg.ControlPlane.Mode != "standalone" || cfg.ControlPlane.Role != "leader" {
		t.Fatalf("control plane defaults = %#v", cfg.ControlPlane)
	}
	if cfg.ControlPlane.Heartbeat != "10s" || cfg.ControlPlane.ElectionTimeout != "45s" {
		t.Fatalf("control plane timing defaults = %#v", cfg.ControlPlane)
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
	if cfg.Output.MaxFileBytes != 16*1024*1024 {
		t.Errorf("Output.MaxFileBytes = %d", cfg.Output.MaxFileBytes)
	}
	if cfg.Output.RetainFiles != 0 {
		t.Errorf("Output.RetainFiles = %d", cfg.Output.RetainFiles)
	}
	if cfg.Output.RetainMaxBytes != 4*1024*1024*1024 {
		t.Errorf("Output.RetainMaxBytes = %d", cfg.Output.RetainMaxBytes)
	}
	if cfg.Output.AlertMaxFileBytes != 8*1024*1024 {
		t.Errorf("Output.AlertMaxFileBytes = %d", cfg.Output.AlertMaxFileBytes)
	}
	if cfg.Output.AlertRetainFiles != 0 {
		t.Errorf("Output.AlertRetainFiles = %d", cfg.Output.AlertRetainFiles)
	}
	if cfg.Output.AlertRetainBytes != 256*1024*1024 {
		t.Errorf("Output.AlertRetainBytes = %d", cfg.Output.AlertRetainBytes)
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
  max_file_bytes: 1048576
  retain_files: 2
  retain_max_bytes: 4194304
  alert_max_file_bytes: 524288
  alert_retain_files: 0
  alert_retain_max_bytes: 1048576
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
	if cfg.Output.MaxFileBytes != 1048576 || cfg.Output.RetainFiles != 2 || cfg.Output.RetainMaxBytes != 4194304 {
		t.Errorf("output event rotation = %d/%d/%d", cfg.Output.MaxFileBytes, cfg.Output.RetainFiles, cfg.Output.RetainMaxBytes)
	}
	if cfg.Output.AlertMaxFileBytes != 524288 || cfg.Output.AlertRetainFiles != 0 || cfg.Output.AlertRetainBytes != 1048576 {
		t.Errorf("output alert rotation = %d/%d/%d", cfg.Output.AlertMaxFileBytes, cfg.Output.AlertRetainFiles, cfg.Output.AlertRetainBytes)
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

func TestLoadTOMLIncludeComms(t *testing.T) {
	toml := `
[output]
dir = "/tmp/providapt-toml"
format = "json"
max_file_bytes = 2097152
retain_files = 3
retain_max_bytes = 8388608
alert_max_file_bytes = 1048576
alert_retain_files = 1
alert_retain_max_bytes = 2097152

[api]
rest = ":18080"
grpc = ":50051"

[capture]
enable_net = true
include_comms = ["/usr/bin/Curl", "bash", "curl"]
exclude_comms = ["SystemD"]

[analyzer]
scan_interval = "5s"
`
	path := writeTempFile(t, "config.*.toml", toml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load TOML: %v", err)
	}
	if cfg.Output.Dir != "/tmp/providapt-toml" {
		t.Fatalf("output dir = %q", cfg.Output.Dir)
	}
	if cfg.API.REST != ":18080" {
		t.Fatalf("api rest = %q", cfg.API.REST)
	}
	if cfg.Output.MaxFileBytes != 2097152 || cfg.Output.RetainFiles != 3 || cfg.Output.RetainMaxBytes != 8388608 {
		t.Fatalf("output event rotation = %d/%d/%d", cfg.Output.MaxFileBytes, cfg.Output.RetainFiles, cfg.Output.RetainMaxBytes)
	}
	if cfg.Output.AlertMaxFileBytes != 1048576 || cfg.Output.AlertRetainFiles != 1 || cfg.Output.AlertRetainBytes != 2097152 {
		t.Fatalf("output alert rotation = %d/%d/%d", cfg.Output.AlertMaxFileBytes, cfg.Output.AlertRetainFiles, cfg.Output.AlertRetainBytes)
	}
	if got := cfg.Capture.IncludeComms; len(got) != 2 || got[0] != "curl" || got[1] != "bash" {
		t.Fatalf("include_comms = %#v, want [curl bash]", got)
	}
	if got := cfg.Capture.ExcludeComms; len(got) != 1 || got[0] != "systemd" {
		t.Fatalf("exclude_comms = %#v, want [systemd]", got)
	}
	if cfg.Analyzer.ScanInterval.Duration != int64(5*time.Second) {
		t.Fatalf("scan_interval = %d, want %d", cfg.Analyzer.ScanInterval.Duration, int64(5*time.Second))
	}
}

func TestLoadTOMLWithLeadingComments(t *testing.T) {
	toml := `
# local development config

[output]
dir = "/tmp/providapt-commented-toml"

[api]
rest = ":18080"
`
	path := writeTempFile(t, "config.*.toml", toml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load TOML with comments: %v", err)
	}
	if cfg.Output.Dir != "/tmp/providapt-commented-toml" {
		t.Fatalf("output dir = %q", cfg.Output.Dir)
	}
	if cfg.API.REST != ":18080" {
		t.Fatalf("api rest = %q", cfg.API.REST)
	}
}

func TestCommAllowedNormalizesCommandNames(t *testing.T) {
	include := []string{"/usr/bin/Curl", "bash"}
	if !CommAllowed("curl", include) {
		t.Fatal("curl should be allowed")
	}
	if !CommAllowed("CURL", include) {
		t.Fatal("CURL should be allowed")
	}
	if !CommAllowed("/bin/bash", include) {
		t.Fatal("/bin/bash should be allowed")
	}
	if CommAllowed("wget", include) {
		t.Fatal("wget should not be allowed")
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

	cfg.API.AuthRoles["operator-key"] = "operator"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("operator role should be built in: %v", err)
	}

	cfg.API.AuthRoles["bad-key"] = "owner"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestValidateCustomAuthRolePermissions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.API.AuthRoles = map[string]string{"ops-key": "responder"}
	cfg.API.AuthPermissions = map[string][]string{
		"responder": {"GET:/api/v1/control/fleet"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate custom role: %v", err)
	}
}

func TestAIStabilityEnvOverrides(t *testing.T) {
	t.Setenv("PROVIDAPT_AI_PROVIDER", "openai")
	t.Setenv("PROVIDAPT_AI_ENDPOINT", "https://llm.example/v1/chat/completions")
	t.Setenv("PROVIDAPT_AI_MODEL", "security-model")
	t.Setenv("PROVIDAPT_AI_TIMEOUT", "15s")
	t.Setenv("PROVIDAPT_AI_MAX_RETRIES", "3")
	t.Setenv("PROVIDAPT_AI_RETRY_BACKOFF", "500ms")
	t.Setenv("PROVIDAPT_AI_CIRCUIT_BREAKER_THRESHOLD", "5")
	t.Setenv("PROVIDAPT_AI_CIRCUIT_BREAKER_COOLDOWN", "2m")
	t.Setenv("PROVIDAPT_AI_MAX_PROMPT_BYTES", "4096")
	t.Setenv("PROVIDAPT_AI_FALLBACK_WITHOUT_LLM", "false")

	cfg, err := Load(filepath.Join(t.TempDir(), "missing.toml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AI.Provider != "openai" || cfg.AI.Endpoint == "" || cfg.AI.Model != "security-model" {
		t.Fatalf("AI identity overrides not applied: %+v", cfg.AI)
	}
	if cfg.AI.Timeout != "15s" || cfg.AI.MaxRetries != 3 || cfg.AI.RetryBackoff != "500ms" {
		t.Fatalf("AI retry overrides not applied: %+v", cfg.AI)
	}
	if cfg.AI.CircuitBreakerThreshold != 5 || cfg.AI.CircuitBreakerCooldown != "2m" || cfg.AI.MaxPromptBytes != 4096 {
		t.Fatalf("AI stability overrides not applied: %+v", cfg.AI)
	}
	if cfg.AI.FallbackWithoutLLM {
		t.Fatalf("fallback override not applied: %+v", cfg.AI)
	}
}

func TestPolicyEnvOverrides(t *testing.T) {
	t.Setenv("PROVIDAPT_POLICY_ENABLED", "true")
	t.Setenv("PROVIDAPT_POLICY_ENDPOINT", "https://control.example.test:8443")
	t.Setenv("PROVIDAPT_POLICY_API_KEY", "policy-key")
	t.Setenv("PROVIDAPT_POLICY_POLL_INTERVAL", "15s")
	t.Setenv("PROVIDAPT_POLICY_BUNDLE_DIR", "/var/lib/providapt/policies")
	t.Setenv("PROVIDAPT_POLICY_ENABLE_TLS", "true")
	t.Setenv("PROVIDAPT_POLICY_CA_FILE", "/etc/providapt/ca.pem")

	cfg, err := Load(t.TempDir() + "/missing.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Policy.Enabled {
		t.Fatal("policy should be enabled")
	}
	if cfg.Policy.Endpoint != "https://control.example.test:8443" {
		t.Fatalf("endpoint = %q", cfg.Policy.Endpoint)
	}
	if cfg.Policy.APIKey != "policy-key" || cfg.Policy.PollInterval != "15s" {
		t.Fatalf("policy config = %#v", cfg.Policy)
	}
	if cfg.Policy.BundleDir != "/var/lib/providapt/policies" || !cfg.Policy.EnableTLS || cfg.Policy.CAFile != "/etc/providapt/ca.pem" {
		t.Fatalf("policy tls config = %#v", cfg.Policy)
	}
}

func TestControlPlaneEnvOverrides(t *testing.T) {
	t.Setenv("PROVIDAPT_CONTROL_PLANE_MODE", "active-passive")
	t.Setenv("PROVIDAPT_CONTROL_PLANE_NODE_ID", "cp-1")
	t.Setenv("PROVIDAPT_CONTROL_PLANE_ROLE", "follower")
	t.Setenv("PROVIDAPT_CONTROL_PLANE_LEADER_ID", "cp-0")
	t.Setenv("PROVIDAPT_CONTROL_PLANE_PEERS", "cp-0:18080,cp-1:18080")
	t.Setenv("PROVIDAPT_CONTROL_PLANE_STATE_BACKEND", "s3://providapt-state/control-plane.json")
	t.Setenv("PROVIDAPT_CONTROL_PLANE_HEARTBEAT", "5s")
	t.Setenv("PROVIDAPT_CONTROL_PLANE_ELECTION_TIMEOUT", "20s")
	t.Setenv("PROVIDAPT_CONTROL_PLANE_FAILOVER_READY", "true")

	cfg, err := Load(t.TempDir() + "/missing.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ControlPlane.Mode != "active-passive" || cfg.ControlPlane.NodeID != "cp-1" {
		t.Fatalf("control plane identity = %#v", cfg.ControlPlane)
	}
	if cfg.ControlPlane.Role != "follower" || cfg.ControlPlane.LeaderID != "cp-0" {
		t.Fatalf("control plane leadership = %#v", cfg.ControlPlane)
	}
	if len(cfg.ControlPlane.Peers) != 2 || cfg.ControlPlane.Peers[0] != "cp-0:18080" {
		t.Fatalf("control plane peers = %#v", cfg.ControlPlane.Peers)
	}
	if cfg.ControlPlane.StateBackend != "s3://providapt-state/control-plane.json" || !cfg.ControlPlane.FailoverReady {
		t.Fatalf("control plane state = %#v", cfg.ControlPlane)
	}
	if cfg.ControlPlane.Heartbeat != "5s" || cfg.ControlPlane.ElectionTimeout != "20s" {
		t.Fatalf("control plane timing = %#v", cfg.ControlPlane)
	}
}

func TestValidateControlPlaneSettings(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ControlPlane.Mode = "raft"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid control plane mode")
	}
	cfg = DefaultConfig()
	cfg.ControlPlane.Role = "primary"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid control plane role")
	}
	cfg = DefaultConfig()
	cfg.ControlPlane.Heartbeat = "0s"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid control plane heartbeat")
	}
	cfg = DefaultConfig()
	cfg.ControlPlane.ElectionTimeout = "soon"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid control plane election timeout")
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
	os.Setenv("PROVIDAPT_LICENSE_ACTIVATION_URL", "http://auth-server:19090/v1/activate")
	os.Setenv("PROVIDAPT_LICENSE_SIGNING_KEY", "env:PROVIDAPT_LICENSE_HMAC")
	os.Setenv("PROVIDAPT_LICENSE_HMAC", "shared-secret")
	os.Setenv("PROVIDAPT_LICENSE_REVOKED_IDS", "lic-1, lic-2")
	os.Setenv("PROVIDAPT_LICENSE_GRACE_PERIOD_DAYS", "14")
	os.Setenv("PROVIDAPT_LICENSE_MAX_AGENTS", "25")
	os.Setenv("PROVIDAPT_LICENSE_PUBLIC_KEY_PATH", "/etc/providapt/license.pub")
	os.Setenv("PROVIDAPT_LICENSE_REVOCATION_URL", "https://licenses.example.com/revocations.json")
	os.Setenv("PROVIDAPT_LICENSE_REVOCATION_CACHE", "/var/lib/providapt/revocations.json")
	os.Setenv("PROVIDAPT_LICENSE_REVOCATION_SIG_URL", "https://licenses.example.com/revocations.json.sig")
	os.Setenv("PROVIDAPT_LICENSE_REVOCATION_SIG_CACHE", "/var/lib/providapt/revocations.json.sig")
	os.Setenv("PROVIDAPT_UPGRADE_MANIFEST_URL", "http://auth-server:19090/v1/releases/latest")
	os.Setenv("PROVIDAPT_UPGRADE_DOWNLOAD_URL", "https://downloads.example.com/providapt.tar.gz")
	os.Setenv("PROVIDAPT_UPGRADE_PACKAGE_PATH", "/tmp/providapt-upgrade.tar.gz")
	os.Setenv("PROVIDAPT_UPGRADE_EXPECTED_SHA256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	os.Setenv("PROVIDAPT_UPGRADE_SIGNATURE_PATH", "/tmp/providapt-upgrade.tar.gz.sig")
	os.Setenv("PROVIDAPT_UPGRADE_SIGNING_KEY", "upgrade-signing-secret")
	os.Setenv("PROVIDAPT_UPGRADE_PUBLIC_KEY_PATH", "/etc/providapt/upgrade.pub")
	os.Setenv("PROVIDAPT_UPGRADE_ROLLBACK_PLAN", "snapshot VM before rollout")
	os.Setenv("PROVIDAPT_UPGRADE_APPLY_COMMAND", "/usr/local/bin/providapt-upgrade apply")
	os.Setenv("PROVIDAPT_UPGRADE_ROLLBACK_COMMAND", "/usr/local/bin/providapt-upgrade rollback")
	os.Setenv("PROVIDAPT_UPGRADE_CANARY_PERCENT", "20")
	defer func() {
		os.Unsetenv("PROVIDAPT_LICENSE_PATH")
		os.Unsetenv("PROVIDAPT_LICENSE_ACTIVATION_URL")
		os.Unsetenv("PROVIDAPT_LICENSE_SIGNING_KEY")
		os.Unsetenv("PROVIDAPT_LICENSE_HMAC")
		os.Unsetenv("PROVIDAPT_LICENSE_REVOKED_IDS")
		os.Unsetenv("PROVIDAPT_LICENSE_GRACE_PERIOD_DAYS")
		os.Unsetenv("PROVIDAPT_LICENSE_MAX_AGENTS")
		os.Unsetenv("PROVIDAPT_LICENSE_PUBLIC_KEY_PATH")
		os.Unsetenv("PROVIDAPT_LICENSE_REVOCATION_URL")
		os.Unsetenv("PROVIDAPT_LICENSE_REVOCATION_CACHE")
		os.Unsetenv("PROVIDAPT_LICENSE_REVOCATION_SIG_URL")
		os.Unsetenv("PROVIDAPT_LICENSE_REVOCATION_SIG_CACHE")
		os.Unsetenv("PROVIDAPT_UPGRADE_MANIFEST_URL")
		os.Unsetenv("PROVIDAPT_UPGRADE_DOWNLOAD_URL")
		os.Unsetenv("PROVIDAPT_UPGRADE_PACKAGE_PATH")
		os.Unsetenv("PROVIDAPT_UPGRADE_EXPECTED_SHA256")
		os.Unsetenv("PROVIDAPT_UPGRADE_SIGNATURE_PATH")
		os.Unsetenv("PROVIDAPT_UPGRADE_SIGNING_KEY")
		os.Unsetenv("PROVIDAPT_UPGRADE_PUBLIC_KEY_PATH")
		os.Unsetenv("PROVIDAPT_UPGRADE_ROLLBACK_PLAN")
		os.Unsetenv("PROVIDAPT_UPGRADE_APPLY_COMMAND")
		os.Unsetenv("PROVIDAPT_UPGRADE_ROLLBACK_COMMAND")
		os.Unsetenv("PROVIDAPT_UPGRADE_CANARY_PERCENT")
	}()

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)
	resolveSecrets(cfg)

	if cfg.License.Path != "/etc/providapt/license.yaml" {
		t.Fatalf("license path = %q", cfg.License.Path)
	}
	if cfg.License.ActivationURL != "http://auth-server:19090/v1/activate" {
		t.Fatalf("license activation_url = %q", cfg.License.ActivationURL)
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
	if cfg.License.MaxAgents != 25 {
		t.Fatalf("license max agents = %d", cfg.License.MaxAgents)
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
	if cfg.Upgrade.ManifestURL != "http://auth-server:19090/v1/releases/latest" {
		t.Fatalf("upgrade manifest_url = %q", cfg.Upgrade.ManifestURL)
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
	if cfg.Upgrade.ApplyCommand != "/usr/local/bin/providapt-upgrade apply" {
		t.Fatalf("upgrade apply command = %q", cfg.Upgrade.ApplyCommand)
	}
	if cfg.Upgrade.RollbackCommand != "/usr/local/bin/providapt-upgrade rollback" {
		t.Fatalf("upgrade rollback command = %q", cfg.Upgrade.RollbackCommand)
	}
	if cfg.Upgrade.CanaryPercent != 20 {
		t.Fatalf("upgrade canary percent = %d", cfg.Upgrade.CanaryPercent)
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

func TestValidateBackupConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Backup.Interval != "24h" {
		t.Fatalf("backup interval = %q", cfg.Backup.Interval)
	}
	if cfg.Backup.RetainArchives != 7 {
		t.Fatalf("backup retain = %d", cfg.Backup.RetainArchives)
	}

	cfg.Backup.Interval = "0s"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for zero backup interval")
	}
	cfg.Backup.Interval = "24h"
	cfg.Backup.RetainArchives = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative backup retention")
	}
	cfg.Backup.RetainArchives = 7
	cfg.Backup.MinFreeBytes = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative backup min free bytes")
	}
}

func TestSSOAndTenantConfig(t *testing.T) {
	yaml := `
api:
  auth_enabled: true
  auth_keys: ["tenant-key"]
  auth_roles:
    tenant-key: analyst
  auth_identities:
    tenant-key: Tenant Analyst
  auth_tenants:
    tenant-key: prod
sso:
  trusted_header_auth: true
  user_header: X-SSO-User
  role_header: X-SSO-Role
  tenant_header: X-SSO-Tenant
`
	path := writeTempFile(t, "config.*.yaml", yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.SSO.TrustedHeaderAuth || cfg.SSO.UserHeader != "X-SSO-User" || cfg.SSO.TenantHeader != "X-SSO-Tenant" {
		t.Fatalf("sso config = %#v", cfg.SSO)
	}
	if cfg.API.AuthTenants["tenant-key"] != "prod" {
		t.Fatalf("tenant config = %#v", cfg.API.AuthTenants)
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
  online_ml_enabled: true
  ml_model_dir: /models/current
  ml_deploy_gate_path: /models/current/model-deploy-gate.json
  require_ml_deploy_gate: true
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
	if !cfg.Analyzer.OnlineMLEnabled || !cfg.Analyzer.RequireMLDeployGate {
		t.Fatalf("online ML deploy gate settings not loaded: %+v", cfg.Analyzer)
	}
	if cfg.Analyzer.MLDeployGatePath != "/models/current/model-deploy-gate.json" {
		t.Fatalf("ml_deploy_gate_path = %q", cfg.Analyzer.MLDeployGatePath)
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

func TestComplianceAndSIEMConfig(t *testing.T) {
	yaml := `
compliance:
  retention_days: 365
  max_audit_entries: 25000
  report_dir: /var/lib/providapt/compliance
  report_interval: 12h
  require_approvals: true
  approval_ttl: 2h
  approval_actions:
    - policy.publish
    - upgrade.preflight
siem:
  enabled: true
  provider: splunk
  endpoint: file:///var/log/siem.ndjson
  token: env:PROVIDAPT_TEST_SIEM_TOKEN
  index: providapt
  source_type: providapt:audit
  format: cef
  min_severity: WARNING
  outbox_dir: /var/lib/providapt/siem
  flush_interval: 15s
`
	path := writeTempFile(t, "config.*.yaml", yaml)
	t.Setenv("PROVIDAPT_TEST_SIEM_TOKEN", "hec-token")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Compliance.RetentionDays != 365 || cfg.Compliance.MaxAuditEntries != 25000 {
		t.Fatalf("compliance config = %#v", cfg.Compliance)
	}
	if !cfg.Compliance.RequireApprovals || len(cfg.Compliance.ApprovalActions) != 2 || cfg.Compliance.ApprovalTTL != "2h" || cfg.Compliance.ReportInterval != "12h" {
		t.Fatalf("approval config = %#v", cfg.Compliance)
	}
	if !cfg.SIEM.Enabled || cfg.SIEM.Provider != "splunk" || cfg.SIEM.Token != "hec-token" || cfg.SIEM.Index != "providapt" || cfg.SIEM.SourceType != "providapt:audit" || cfg.SIEM.Format != "cef" || cfg.SIEM.MinSeverity != "WARNING" || cfg.SIEM.FlushInterval != "15s" {
		t.Fatalf("siem config = %#v", cfg.SIEM)
	}
}

func TestValidateCommercialP2Config(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Compliance.RetentionDays = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid compliance retention")
	}
	cfg = DefaultConfig()
	cfg.SIEM.Format = "xml"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid SIEM format")
	}
	cfg = DefaultConfig()
	cfg.SIEM.Provider = "unknown"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid SIEM provider")
	}
	cfg = DefaultConfig()
	cfg.SIEM.FlushInterval = "0s"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid SIEM flush interval")
	}
	cfg = DefaultConfig()
	cfg.Compliance.ApprovalTTL = "0s"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid approval ttl")
	}
	cfg = DefaultConfig()
	cfg.Upgrade.CanaryPercent = 101
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid upgrade canary")
	}
}

func TestSecretResolverSupportsFileAndVaultReferences(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "siem-token")
	if err := os.WriteFile(secretPath, []byte("file-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Secrets.Provider = "vault"
	cfg.Secrets.BaseDir = dir
	cfg.Secrets.Vault = map[string]string{
		"policy/api-key": "vault-policy-key",
	}
	cfg.SIEM.Token = "file:siem-token"
	cfg.Policy.APIKey = "vault:policy/api-key"

	resolveSecrets(cfg)

	if cfg.SIEM.Token != "file-secret" {
		t.Fatalf("siem token = %q", cfg.SIEM.Token)
	}
	if cfg.Policy.APIKey != "vault-policy-key" {
		t.Fatalf("policy api key = %q", cfg.Policy.APIKey)
	}
}

func TestValidateTLSRotationAndSecretProvider(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.RotationCheck = "12h"
	cfg.TLS.RotationRenewBefore = "720h"
	cfg.Secrets.Provider = "vault"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid production settings rejected: %v", err)
	}
	cfg.TLS.RotationCheck = "0s"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid TLS rotation check")
	}
	cfg = DefaultConfig()
	cfg.Secrets.Provider = "unknown"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid secrets provider")
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
