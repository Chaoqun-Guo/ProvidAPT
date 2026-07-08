# ProvidAPT

ProvidAPT is a Linux provenance-based threat detection platform built on eBPF and BPF LSM. It captures kernel-level activity, builds a provenance graph, and supports detection, investigation, audit, support, ticketing, license, and upgrade workflows for production operations.

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue)](https://golang.org)
[![Release](https://img.shields.io/badge/Release-v1.2.2-brightgreen)](CHANGELOG.md)
[![License](https://img.shields.io/badge/License-Apache--2.0-green)](LICENSE)

## Overview

ProvidAPT combines:

- eBPF kernel telemetry collection
- provenance graph construction and query
- threat scoring, alerting, and response
- fleet and control-plane operations
- audit logging, support bundle export, and release governance

## Project Layout

```text
ProvidAPT/
├── cmd/                # binaries and entry points
├── internal/           # engine, policy, storage, and stitching internals
├── pkg/                # public packages: API, config, notify, support, telemetry
├── docs/               # product, developer, architecture, and project docs
├── deploy/             # Helm, Terraform, Ansible, and deployment assets
├── scripts/            # operational helper scripts
├── test/               # integration, benchmark, and validation assets
├── build/              # packaging, docker, and build-time assets
└── examples/           # example configurations and usage samples
```

Detailed documentation for the repository layout is available in `docs/project/project-layout.md`.

## Quick Start

```bash
# Build the full product
make build-core

# Run core tests
make test-core

# Run Linux loader smoke validation on a suitable host
sudo make loader-smoke
```

## eBPF Loader Notes

- ProvidAPT prefers BPF LSM hooks and falls back to kprobe mode when LSM attachment fails at runtime.
- The loader searches for precompiled objects in `build/ebpf/lsm_hooks.bpf.o` and `/usr/local/lib/providapt/ebpf/lsm_hooks.bpf.o`.
- You can override the object path with `PROVIDAPT_BPF_OBJECT_PATH=/path/to/lsm_hooks.bpf.o`.
- If the object file is missing, run `make build-ebpf` before starting `providaptd`.

## Build Outputs

```text
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
| [Getting Started](docs/getting-started/INDEX.md) | Installation, deployment, and first-run guidance |
| [Architecture](docs/architecture/INDEX.md) | System design, data flow, provenance model |
| [User Guide](docs/user-guide/INDEX.md) | CLI, operations, ProvQL, detection rules |
| [Developer Guide](docs/developer/INDEX.md) | API, schema, testing, upgrade, release notes |
| [Project Docs](docs/project/INDEX.md) | Documentation audit, project layout, release consistency checks |
| [Benchmarks](docs/benchmarks/INDEX.md) | Performance and benchmark material |
| [Compliance](docs/compliance/INDEX.md) | Security, privacy, and governance posture |

## Release Status

- Current release target: `v1.2.2`
- Release notes: `docs/developer/release-notes-v1.2.2.md`
- Release checklist: `docs/developer/release-readiness.md`
- Product changelog: `CHANGELOG.md`

## Requirements

- Linux kernel 5.8+ (5.11+ recommended for BPF LSM)
- BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- clang 12+, llvm-strip
- libbpf 1.0+
- Go 1.25+

## License

Apache 2.0
