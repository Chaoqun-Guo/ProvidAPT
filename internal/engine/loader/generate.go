// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-Icmd/bpf/headers" bpf cmd/bpf/probes/lsm/lsm_hooks.bpf.c

package loader
