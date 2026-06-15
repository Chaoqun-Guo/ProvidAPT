// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

func TestRegisterAndGet(t *testing.T) {
	p := &dummyPlugin{name: "test"}
	err := Register(p)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := Get("test")
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Name() != "test" {
		t.Errorf("Name = %q", got.Name())
	}
}

func TestRegisterDuplicate(t *testing.T) {
	p := &dummyPlugin{name: "dup"}
	err := Register(p)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	err = Register(p)
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
}

func TestList(t *testing.T) {
	names := List()
	if len(names) == 0 {
		t.Log("no plugins registered (expected in isolation)")
	}
}

type dummyPlugin struct {
	name string
}

func (d *dummyPlugin) Name() string { return d.name }
func (d *dummyPlugin) Analyse(snap *provenance.Graph) []*Finding {
	return nil
}

// ─── Discovery tests ─────────────────────────────────────────

func TestDiscoverBadDir(t *testing.T) {
	// Non-existent directory — should return error, not panic.
	result, err := Discover("/nonexistent/plugins")
	if err == nil {
		if result != nil {
			t.Errorf("expected nil result for bad dir, got %+v", result)
		}
		return
	}
	t.Logf("Discover bad dir: %v", err)
}

func TestDiscoverEmptyDir(t *testing.T) {
	dir := t.TempDir()
	result, err := Discover(dir)
	if err != nil {
		if err == ErrUnsupported {
			t.Skip("plugin discovery not supported on this platform")
			return
		}
		t.Fatalf("Discover empty dir: %v", err)
	}
	if result == nil {
		t.Fatal("Discover returned nil result without error")
	}
	if len(result.Loaded) != 0 {
		t.Errorf("expected 0 loaded, got %d", len(result.Loaded))
	}
	if len(result.Failed) != 0 {
		t.Errorf("expected 0 failed, got %d: %v", len(result.Failed), result.Failed)
	}
}

func TestDiscoverWithInvalidSO(t *testing.T) {
	dir := t.TempDir()
	badSO := filepath.Join(dir, "bad.so")
	if err := os.WriteFile(badSO, []byte("not a valid plugin"), 0644); err != nil {
		t.Fatalf("write bad.so: %v", err)
	}

	result, err := Discover(dir)
	if err != nil {
		if err == ErrUnsupported {
			t.Skip("plugin discovery not supported on this platform")
			return
		}
		t.Fatalf("Discover with invalid .so: %v", err)
	}
	if result == nil {
		t.Fatal("Discover returned nil result without error")
	}
	t.Logf("Result: loaded=%d, failed=%d", len(result.Loaded), len(result.Failed))
}

func TestDiscoverNonSODir(t *testing.T) {
	dir := t.TempDir()
	txtFile := filepath.Join(dir, "readme.txt")
	if err := os.WriteFile(txtFile, []byte("hello"), 0644); err != nil {
		t.Fatalf("write readme.txt: %v", err)
	}

	result, err := Discover(dir)
	if err != nil {
		if err == ErrUnsupported {
			t.Skip("plugin discovery not supported on this platform")
			return
		}
		t.Fatalf("Discover non-.so dir: %v", err)
	}
	if result == nil {
		t.Fatal("Discover returned nil result without error")
	}
	if len(result.Loaded) != 0 {
		t.Errorf("expected 0 loaded, got %d", len(result.Loaded))
	}
	if len(result.Failed) != 0 {
		t.Errorf("expected 0 failed, got %d: %v", len(result.Failed), result.Failed)
	}
}

func TestErrUnsupported(t *testing.T) {
	if ErrUnsupported == nil {
		t.Fatal("ErrUnsupported should not be nil")
	}
	t.Logf("ErrUnsupported: %v", ErrUnsupported)
}

func TestDiscoveryResultType(t *testing.T) {
	r := &DiscoveryResult{
		Loaded: []string{"a", "b"},
		Failed: []string{"c.so"},
	}
	if len(r.Loaded) != 2 {
		t.Errorf("Loaded = %d", len(r.Loaded))
	}
	if len(r.Failed) != 1 {
		t.Errorf("Failed = %d", len(r.Failed))
	}
}
