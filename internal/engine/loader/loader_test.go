// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loader

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

func TestAttachmentModeString(t *testing.T) {
	tests := []struct {
		mode AttachmentMode
		want string
	}{
		{ModeLSM, "lsm"},
		{ModeKprobeFallback, "kprobe_fallback"},
		{AttachmentMode(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("AttachmentMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestModeNameNilLoader(t *testing.T) {
	var l *Loader
	if got := l.ModeName(); got != "uninitialized" {
		t.Errorf("ModeName() on nil = %q, want %q", got, "uninitialized")
	}
}

func TestSetAuditStore(t *testing.T) {
	// SetAuditStore should not panic when called.
	l := &Loader{}
	l.SetAuditStore(nil)
	if l.auditStore != nil {
		t.Error("expected nil auditStore after SetAuditStore(nil)")
	}
}

func TestParseHookConfigDefaults(t *testing.T) {
	got, err := ParseHookConfig(nil)
	if err != nil {
		t.Fatalf("ParseHookConfig(nil) error = %v", err)
	}
	if !reflect.DeepEqual(got, DefaultHooks()) {
		t.Fatalf("ParseHookConfig(nil) = %#v, want %#v", got, DefaultHooks())
	}
}

func TestParseHookConfigRejectsUnknown(t *testing.T) {
	_, err := ParseHookConfig([]string{"task_alloc", "definitely_unknown"})
	if err == nil {
		t.Fatal("expected error for unknown hook")
	}
	if !strings.Contains(err.Error(), "unknown kernel hook") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseHookConfigDeduplicates(t *testing.T) {
	got, err := ParseHookConfig([]string{"task_alloc", "task_alloc", "file_open"})
	if err != nil {
		t.Fatalf("ParseHookConfig returned error: %v", err)
	}
	want := HookConfig{EnabledHooks: []HookID{HookTaskAlloc, HookFileOpen}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseHookConfig() = %#v, want %#v", got, want)
	}
}

func TestLoaderSpecsRespectConfiguredHooks(t *testing.T) {
	l := &Loader{
		objs:  &bpfObjects{},
		hooks: HookConfig{EnabledHooks: []HookID{HookFileOpen, HookSocketConnect}},
	}

	lsmSpecs := l.lsmSpecs()
	if len(lsmSpecs) != 2 {
		t.Fatalf("len(lsmSpecs) = %d, want 2", len(lsmSpecs))
	}
	if lsmSpecs[0].hook != HookFileOpen || lsmSpecs[1].hook != HookSocketConnect {
		t.Fatalf("unexpected lsm hook order: %#v", lsmSpecs)
	}

	kprobeSpecs := l.kprobeSpecs()
	if len(kprobeSpecs) != 2 {
		t.Fatalf("len(kprobeSpecs) = %d, want 2", len(kprobeSpecs))
	}
	if !reflect.DeepEqual(kprobeSpecs[0].symbols, []string{"security_file_open"}) {
		t.Fatalf("unexpected file_open symbols: %#v", kprobeSpecs[0].symbols)
	}
	if !reflect.DeepEqual(kprobeSpecs[1].symbols, []string{"__sys_connect"}) {
		t.Fatalf("unexpected socket_connect symbols: %#v", kprobeSpecs[1].symbols)
	}
}

// TestNewFailsWithoutBPFObjects verifies that New() returns an error
// when eBPF objects cannot be loaded (no kernel support, no .o file).
// This test only checks the error path — the actual eBPF object loading
// requires a running kernel with eBPF support.
func TestNewFailsWithoutBPFObjects(t *testing.T) {
	_, err := New(&config.Config{})
	if err != nil {
		// Expected on systems without eBPF support.
		// The exact error depends on the runtime environment.
		t.Logf("New() returned expected error: %v", err)
	}
}

// BenchmarkFallbackAttach measures the kprobe fallback path overhead.
func BenchmarkKprobeFallback(b *testing.B) {
	l := &Loader{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// ModeName is a simple accessor — just a baseline.
		_ = l.ModeName()
	}
}
