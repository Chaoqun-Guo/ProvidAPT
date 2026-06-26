// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loader

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const bpfObjectEnvVar = "PROVIDAPT_BPF_OBJECT_PATH"

var defaultLSMBpfObjectPaths = []string{
	"/usr/local/lib/providapt/ebpf/lsm_hooks.bpf.o",
	"build/ebpf/lsm_hooks.bpf.o",
}

var defaultKprobeBpfObjectPaths = []string{
	"/usr/local/lib/providapt/ebpf/kprobe_fallback.bpf.o",
	"build/ebpf/kprobe_fallback.bpf.o",
}

func bpfObjectPaths(mode string) []string {
	if path := strings.TrimSpace(os.Getenv(bpfObjectEnvVar)); path != "" {
		return []string{path}
	}

	source := defaultLSMBpfObjectPaths
	if mode == "kprobe" {
		source = defaultKprobeBpfObjectPaths
	}
	paths := make([]string, len(source))
	copy(paths, source)
	return paths
}

func formatBpfLoadError(paths []string, errs []error) error {
	if len(errs) == 0 {
		return fmt.Errorf("loadBpf: no search paths configured")
	}

	allMissing := true
	details := make([]string, 0, len(errs))
	for i, err := range errs {
		if !errors.Is(err, os.ErrNotExist) {
			allMissing = false
		}
		path := "<unknown>"
		if i < len(paths) {
			path = paths[i]
		}
		details = append(details, fmt.Sprintf("%s: %v", path, err))
	}

	if allMissing {
		return fmt.Errorf("loadBpf: no precompiled eBPF object found; searched %s; run `make build-ebpf` or set %s; details: %s",
			strings.Join(paths, ", "),
			bpfObjectEnvVar,
			strings.Join(details, "; "),
		)
	}

	return fmt.Errorf("loadBpf: all paths failed: %s", strings.Join(details, "; "))
}
