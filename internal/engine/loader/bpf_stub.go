//go:build linux

// This is a build stub for environments without the bpf2go-generated
// eBPF types (e.g., CI, Docker).  Remove this file once bpf2go
// generated types are committed to the repository.
//
// To generate the real types:
//
//	bpf2go -cc clang -cflags "-Icmd/bpf/headers" bpf cmd/bpf/probes/lsm/lsm_hooks.bpf.c

package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type bpfObjects struct {
	ProbeFileOpen        *ebpf.Program
	ProbeBprmCheck       *ebpf.Program
	ProbeTaskAlloc       *ebpf.Program
	ProbeTaskFree        *ebpf.Program
	ProbeSocketConnect   *ebpf.Program
	ProbeFilePermission  *ebpf.Program
	RawTpSchedProcessFork *ebpf.Program
	PidWhitelist         *ebpf.Map
	TaintMap             *ebpf.Map
	SampleCounters       *ebpf.Map
	HotPaths             *ebpf.Map
	Rb                   *ebpf.Map
}

func (o *bpfObjects) Close() error { return nil }

func loadBpfObjects(objs *bpfObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF stub: no BPF device available")
}
