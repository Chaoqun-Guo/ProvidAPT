# eBPF Development Guide

## Overview

ProvidAPT uses eBPF programs to capture kernel-level provenance events. The eBPF sources live in `cmd/bpf/probes/` and are compiled to `.bpf.o` objects loaded by the Go userspace agent.

## Directory Structure

```
cmd/bpf/
├── headers/          # Common eBPF headers (vmlinux, helpers)
├── probes/
│   ├── lsm/          # LSM hooks (file_open, bprm_check, defense)
│   ├── task/         # Task tracing (memory, process)
│   └── net/          # Network tracing (socket_connect)
└── Makefile          # x86_64-only build (use build/build_ebpf.sh for multi-arch)
```

## Building eBPF Objects

Requires: `clang`, `llvm`, `libbpf-dev`, kernel headers.

```bash
# Build all eBPF objects
make build-ebpf

# Generate Go bindings (bpf2go)
make generate-ebpf

# Cross-arch build
bash build/build_ebpf.sh
```

Output goes to `build/ebpf/*.bpf.o`.

## Adding a New Probe

1. Create the eBPF C program in `cmd/bpf/probes/<category>/`
2. Add build rule to `cmd/bpf/Makefile` and `Makefile`
3. Create a Go loader in `internal/engine/loader/` using `cilium/ebpf`
4. Attach the probe in the daemon startup sequence

## Testing

```bash
# Linux-only smoke test (requires root + eBPF)
make loader-smoke
```

## CO-RE (Compile Once, Run Everywhere)

ProvidAPT uses BTF-based CO-RE for cross-kernel compatibility. The compiled `.bpf.o` objects are portable across kernels 5.4+ without recompilation.

See `test/integration/kernel-test/` for the kernel compatibility test matrix.
