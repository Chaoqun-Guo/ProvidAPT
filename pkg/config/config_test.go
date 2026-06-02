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

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid json}"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
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
