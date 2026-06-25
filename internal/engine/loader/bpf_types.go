// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// bpfObjects mirrors the maps and programs declared in
// cmd/bpf/probes/lsm/lsm_hooks.bpf.c and tracepoints.bpf.c.
// Shared between bpf_stub.go (!bpf) and bpf_loader.go (bpf).
type bpfObjects struct {
	ProbeFileOpen       *ebpf.Program `ebpf:"probe_file_open"`
	ProbeBprmCheck      *ebpf.Program `ebpf:"probe_bprm_check"`
	ProbeTaskAlloc      *ebpf.Program `ebpf:"probe_task_alloc"`
	ProbeTaskFree       *ebpf.Program `ebpf:"probe_task_free"`
	ProbeSocketConnect  *ebpf.Program `ebpf:"probe_socket_connect"`
	ProbeFilePermission *ebpf.Program `ebpf:"probe_file_permission"`
	PidWhitelist        *ebpf.Map     `ebpf:"pid_whitelist"`
	TaintMap            *ebpf.Map     `ebpf:"taint_map"`
	SampleCounters      *ebpf.Map     `ebpf:"sample_counters"`
	HotPaths            *ebpf.Map     `ebpf:"hot_paths"`
	Rb                  *ebpf.Map     `ebpf:"rb"`
}

func (o *bpfObjects) Close() error {
	var errs []error
	for _, prog := range []*ebpf.Program{
		o.ProbeFileOpen, o.ProbeBprmCheck, o.ProbeTaskAlloc,
		o.ProbeTaskFree, o.ProbeSocketConnect, o.ProbeFilePermission,
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
