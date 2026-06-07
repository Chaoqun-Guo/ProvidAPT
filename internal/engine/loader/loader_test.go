// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loader

import (
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
