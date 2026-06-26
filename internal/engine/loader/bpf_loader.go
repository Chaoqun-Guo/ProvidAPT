// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux && bpf

// Real eBPF loader 鈥-loads pre-compiled .bpf.o files from the
// filesystem at runtime.  Requires:
//   make build-ebpf                    # compile .bpf.c 鈫-.bpf.o
//   go build -tags bpf ./cmd/...    # enable real eBPF loading
//
// The .o files are searched at well-known paths:
//   /usr/local/lib/providapt/ebpf/  (production install)
//   build/ebpf/                     (development build)

package loader

import (
	"bytes"
	"os"

	"github.com/cilium/ebpf"
)

// loadBpf loads eBPF objects from a pre-compiled BPF object file.
// It searches bpfObjectPaths and returns the first successful load.
func loadBpf(objs *bpfObjects, opts *ebpf.CollectionOptions) error {
	return loadBpfForMode(objs, opts, "lsm")
}

func loadBpfForMode(objs *bpfObjects, opts *ebpf.CollectionOptions, mode string) error {
	paths := bpfObjectPaths(mode)
	var errs []error
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := spec.LoadAndAssign(objs, opts); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
	}
	return formatBpfLoadError(paths, errs)
}
