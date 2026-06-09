// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !bpf

// This file provides build-time stub types for environments without
// real eBPF support (CI, Docker, cross-compilation).
//
// To load real eBPF objects:
//   make build-ebpf                    # compile .bpf.c 鈫?.bpf.o
//   go build -tags bpf ./cmd/...    # use real loader
//
// The bpf2go-generated file (bpf_bpfel.go / bpf_bpfeb.go) can also
// be checked in directly.  See generate.go for generation commands.

package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func (o *bpfObjects) Close() error {
	var errs []error
	for _, prog := range []*ebpf.Program{
		o.ProbeFileOpen, o.ProbeBprmCheck, o.ProbeTaskAlloc,
		o.ProbeTaskFree, o.ProbeSocketConnect, o.ProbeFilePermission,
		o.RawTpSchedProcessFork,
	} {
		if prog != nil {
			if err := prog.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, m := range []*ebpf.Map{
		o.PidWhitelist, o.TaintMap, o.SampleCounters, o.HotPaths, o.Rb,
	} {
		if m != nil {
			if err := m.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close bpf objects: %v", errs)
	}
	return nil
}

// loadBpf is a stub that returns an error.  Build with -tags bpf and
// pre-compiled .bpf.o files to use the real loader.
func loadBpf(objs *bpfObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF stub: no BPF device available (compile with -tags bpf to enable)")
}
