# ProvidAPT

ProvidAPT is a Linux provenance-based threat detection platform built on eBPF and BPF LSM. It captures kernel-level activity, constructs a provenance graph, and supports detection, investigation, and operational control workflows for advanced threats.

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache--2.0-green)](LICENSE)

## Overview

ProvidAPT combines kernel telemetry, provenance graph construction, policy evaluation, audit logging, support bundle collection, and commercial control-plane workflows such as fleet management, ticketing, license validation, and upgrade preflight.

## Project Structure

```text
ProvidAPT/
├── cmd/                # binaries and entry points
├── internal/           # core engine, policy, storage, stitching
├── pkg/                # public libraries, API, config, audit, support bundle
├── docs/               # user, developer, architecture, compliance docs
├── scripts/            # operational helper scripts
├── test/               # integration, benchmark, and fuzz coverage
├── build/              # packaging and build assets
└── deploy/             # deployment manifests and examples
```

## Quick Start

```bash
# Build core components
make v1

# Run tests
make test

# Run Linux loader smoke validation on a suitable host
sudo make loader-smoke
```
## eBPF Loader Notes

- ProvidAPT prefers **BPF LSM** hooks and automatically falls back to **kprobe mode** when LSM attachment fails at runtime.
- The loader searches precompiled objects in `build/ebpf/lsm_hooks.bpf.o` and `/usr/local/lib/providapt/ebpf/lsm_hooks.bpf.o`.
- You can override the object path with `PROVIDAPT_BPF_OBJECT_PATH=/path/to/lsm_hooks.bpf.o`.
- If the object file is missing, run `make v1-ebpf` before starting `providaptd`.

## Build Outputs

```
build/bin/providaptd          # Main daemon
build/bin/providaptctl        # CLI control
build/bin/providapt-watchdog  # Watchdog
build/bin/providapt-verify    # System check
build/bin/providapt-deanon    # De-anonymization
build/bin/providapt-heal      # Auto-healing
build/ebpf/*.bpf.o            # Compiled eBPF programs
```

## Documentation

| Section | Description |
| ------- | ----------- |
| [Getting Started](docs/getting-started/INDEX.md) | Installation, deployment |
| [Architecture](docs/architecture/INDEX.md) | System design, data flow |
| [User Guide](docs/user-guide/INDEX.md) | CLI, ProvQL, detection rules |
| [Developer Guide](docs/developer/INDEX.md) | API, schema, changelog, release notes |
| [Benchmarks](docs/benchmarks/INDEX.md) | Performance data |
| [Compliance](docs/compliance/INDEX.md) | Security, privacy |
| [Documentation Audit](docs/DOCUMENTATION_AUDIT.md) | Audience-based document classification |

## Requirements

- Linux kernel 5.8+ (5.11+ for LSM BPF)
- BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- clang 12+, llvm-strip
- libbpf 1.0+
- Go 1.22+

## License

Apache 2.0


