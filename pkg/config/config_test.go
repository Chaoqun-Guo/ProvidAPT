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
	if len(cfg.Kernel.Hooks) == 0 {
		t.Error("expected default hooks")
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
	defer func() {
		os.Unsetenv("PROVIDAPT_LOG_LEVEL")
		os.Unsetenv("PROVIDAPT_OUTPUT_DIR")
		os.Unsetenv("PROVIDAPT_CAPTURE_ENABLE_NET")
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
