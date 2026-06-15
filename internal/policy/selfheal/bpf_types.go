// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package selfheal

import "github.com/cilium/ebpf"

// bpfObjects mirrors the eBPF programs and maps used by the self-healing
// module for integrity verification and reloading.
//
// The ebpf struct tags must match the program/map names in the compiled
// .bpf.o ELF files (function names for programs, SEC(".maps") struct names
// for maps).
type bpfObjects struct {
	// ── Programs ────────────────────────────────────────────────
	ProbeFileOpen       *ebpf.Program `ebpf:"probe_file_open"`
	ProbeBprmCheck      *ebpf.Program `ebpf:"probe_bprm_check"`
	ProbeTaskAlloc      *ebpf.Program `ebpf:"probe_task_alloc"`
	ProbeSocketConnect  *ebpf.Program `ebpf:"probe_socket_connect"`
	ProbeNetConnect     *ebpf.Program `ebpf:"probe_net_connect"`
	ProbeFilePermission *ebpf.Program `ebpf:"probe_file_permission"`

	// ── Maps ────────────────────────────────────────────────────
	Rb           *ebpf.Map `ebpf:"rb"`
	ProcMap      *ebpf.Map `ebpf:"proc_map"`
	PidWhitelist *ebpf.Map `ebpf:"pid_whitelist"`
	TaintMap     *ebpf.Map `ebpf:"taint_map"`

	// ── Sub-collections for multi-object files ──────────────────
	// When a combined .o file uses multiple SEC(".maps") sections,
	// these hold the sub-collections.
	LsmHooks *bpfLsmHooks
	Network  *bpfNetwork
}

// bpfLsmHooks holds programs and maps from lsm_hooks.bpf.c.
type bpfLsmHooks struct {
	ProbeFileOpen       *ebpf.Program `ebpf:"probe_file_open"`
	ProbeBprmCheck      *ebpf.Program `ebpf:"probe_bprm_check"`
	ProbeTaskAlloc      *ebpf.Program `ebpf:"probe_task_alloc"`
	ProbeTaskFree       *ebpf.Program `ebpf:"probe_task_free"`
	ProbeSocketConnect  *ebpf.Program `ebpf:"probe_socket_connect"`
	ProbeFilePermission *ebpf.Program `ebpf:"probe_file_permission"`
	Rb                  *ebpf.Map     `ebpf:"rb"`
	ProcMap             *ebpf.Map     `ebpf:"proc_map"`
	PidWhitelist        *ebpf.Map     `ebpf:"pid_whitelist"`
	TaintMap            *ebpf.Map     `ebpf:"taint_map"`
	SampleCounters      *ebpf.Map     `ebpf:"sample_counters"`
}

// bpfNetwork holds programs and maps from network.bpf.c.
type bpfNetwork struct {
	ProbeNetConnect *ebpf.Program `ebpf:"probe_net_connect"`
	ProbeSocketConnect *ebpf.Program `ebpf:"probe_socket_connect"`
	ProbeSocketAccept *ebpf.Program `ebpf:"probe_socket_accept"`
	RbNetwork         *ebpf.Map     `ebpf:"rb_network"`
}
