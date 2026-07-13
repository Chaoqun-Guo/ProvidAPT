// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !bpf

// This file provides build-time stub types for environments without
// real eBPF support (CI, Docker, cross-compilation).
//
// To load real eBPF objects:

//   go build -tags bpf ./cmd/...    # use real loader
//
// The bpf2go-generated file (bpf_bpfel.go / bpf_bpfeb.go) can also
// be checked in directly.  See generate.go for generation commands.

package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// loadBpf is a stub that returns an error.  Build with -tags bpf and
// pre-compiled .bpf.o files to use the real loader.
func loadBpf(objs *bpfObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF stub: no BPF device available (compile with -tags bpf to enable)")
}

func loadBpfForMode(objs *bpfObjects, opts *ebpf.CollectionOptions, mode string) error {
	return loadBpf(objs, opts)
}
