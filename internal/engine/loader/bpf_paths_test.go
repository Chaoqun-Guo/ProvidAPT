// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loader

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestBpfObjectPathsDefault(t *testing.T) {
	t.Setenv(bpfObjectEnvVar, "")

	got := bpfObjectPaths()
	if len(got) != len(defaultBpfObjectPaths) {
		t.Fatalf("len(bpfObjectPaths()) = %d, want %d", len(got), len(defaultBpfObjectPaths))
	}
	for i := range defaultBpfObjectPaths {
		if got[i] != defaultBpfObjectPaths[i] {
			t.Fatalf("bpfObjectPaths()[%d] = %q, want %q", i, got[i], defaultBpfObjectPaths[i])
		}
	}
}

func TestBpfObjectPathsEnvOverride(t *testing.T) {
	t.Setenv(bpfObjectEnvVar, "/tmp/custom-loader.bpf.o")

	got := bpfObjectPaths()
	if len(got) != 1 || got[0] != "/tmp/custom-loader.bpf.o" {
		t.Fatalf("bpfObjectPaths() = %#v, want custom override", got)
	}
}

func TestFormatBpfLoadErrorMissingObjects(t *testing.T) {
	paths := []string{"/a/one.bpf.o", "/b/two.bpf.o"}
	err := formatBpfLoadError(paths, []error{os.ErrNotExist, os.ErrNotExist})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no precompiled eBPF object found") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(msg, "make v1-ebpf") || !strings.Contains(msg, bpfObjectEnvVar) {
		t.Fatalf("expected remediation guidance in error: %v", err)
	}
}

func TestFormatBpfLoadErrorMixedFailures(t *testing.T) {
	paths := []string{"/a/one.bpf.o", "/b/two.bpf.o"}
	err := formatBpfLoadError(paths, []error{os.ErrNotExist, errors.New("invalid ELF")})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if strings.Contains(msg, "no precompiled eBPF object found") {
		t.Fatalf("expected generic failure, got missing-object message: %v", err)
	}
	if !strings.Contains(msg, "invalid ELF") {
		t.Fatalf("expected underlying failure detail, got: %v", err)
	}
}
