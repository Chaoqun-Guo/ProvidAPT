# ProvidAPT

Linux 全系统溯源记录工具，基于 eBPF LSM 技术，用于 APT 攻击分析与溯源。

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache--2.0-green)](LICENSE)

## Overview

ProvidAPT is a provenance-based threat detection platform that captures kernel-level events via eBPF, constructs a W3C PROV-compliant provenance graph, and applies multi-stage detection (rule-based, ML, anomaly) to identify APT attack patterns. The system supports evolution from v1 (core eBPF monitoring) to v2.2 (distributed stitching, active defense, supply chain forensics).

## Project Structure

```
ProvidAPT/
├── cmd/                        # Entry points
│   ├── agent/
│   │   ├── daemon/             # providaptd — main monitoring daemon
│   │   └── watchdog/           # providapt-watchdog — self-healing watchdog
│   ├── cli/
│   │   ├── providaptctl/       # CLI control tool
│   │   ├── providapt-verify/   # System verification
│   │   ├── providapt-heal/     # Automated remediation
│   │   └── providapt-deanon/   # De-anonymization tool
│   ├── collector/              # v2.2 distributed collector
│   └── bpf/                    # eBPF C programs
│       ├── headers/            # vmlinux.h + custom headers
│       └── probes/             # Probes organized by function
│           ├── lsm/            # LSM hooks (file_open, bprm_check…)
│           ├── net/            # Network hooks
│           └── task/           # kprobes, tracepoints, memory, container
│
├── internal/                   # Core libraries
│   ├── engine/                 # Provenance graph + taint tracking
│   │   ├── collector/          # eBPF ring buffer reader
│   │   ├── pipeline/           # Zero-copy event pipeline
│   │   ├── provenance/         # W3C PROV provenance graph
│   │   ├── analyzer/           # APT pattern analyzer
│   │   ├── query/              # ProvQL query engine
│   │   ├── loader/             # eBPF program loader
│   │   ├── control/            # Runtime control (whitelist, taint, sampling)
│   │   ├── stream/             # NFA-based stream scanner
│   │   ├── predict/            # Attack prediction & ATT&CK mapping
│   │   ├── syscall/            # Syscall table definitions
│   │   ├── edgereduce/         # Edge deduplication & aggregation
│   │   ├── graphquery/         # Graph query optimization
│   │   ├── profile/            # Performance profiling
│   │   ├── ratelimit/          # Event rate limiting
│   │   ├── chain/              # Process chain tracking
│   │   ├── container/          # Container-aware monitoring
│   │   ├── fold/               # Graph folding
│   │   ├── memtrack/           # Memory tracking
│   │   ├── netmon/             # Network monitoring
│   │   ├── netfinger/          # Network fingerprinting
│   │   ├── taint/              # Taint propagation engine
│   │   ├── viz/                # Graph visualization
│   │   ├── ja3/                # JA3 TLS fingerprinting
│   │   ├── memforensic/        # Memory forensics
│   │   └── opt/                # Graph optimization passes
│   │
│   ├── storage/                # Storage layer
│   │   ├── pebblestore/        # Pebble-based event store
│   │   ├── cache/              # LRU cache
│   │   ├── grpcexport/         # gRPC event export
│   │   ├── format/             # Storage format (JSON, Parquet)
│   │   ├── export/             # Graph export (JSON, GraphML, PROV-JSON)
│   │   ├── graphdb/            # In-memory graph database
│   │   └── snapshot/           # Snapshot management
│   │
│   ├── stitcher/               # Cross-host graph stitching
│   │   ├── stitch/             # Graph merging logic
│   │   ├── graphsketch/        # Feature vector entropy detection
│   │   ├── server/             # Stitching server
│   │   ├── dist/               # Distributed coordination
│   │   └── orch/               # Orchestration
│   │
│   └── policy/                 # Policy engine + detection rules
│       ├── alert/              # Alert management
│       ├── incident/           # Incident clustering
│       ├── response/           # Response orchestration
│       ├── defense/            # Self-defense
│       ├── selfheal/           # Automated healing
│       ├── heal/               # Impact assessment
│       ├── sigma/              # Sigma rule engine
│       ├── honeypot/           # Deception/honeypot
│       ├── armor/              # System hardening
│       ├── rulescanner/        # Rule-based scanning
│       ├── blastradius/        # Blast radius analysis
│       ├── deception/          # Active deception
│       ├── supplychain/        # Supply chain monitoring
│       ├── adaptive/           # Adaptive response levels
│       └── mgmt/               # Management interface
│
├── pkg/                        # Public libraries
│   ├── api/                    # HTTP/gRPC API
│   │   └── proto/              # Protobuf definitions
│   │       ├── core/           # Core protobuf types
│   │       ├── container/      # Container protobuf types
│   │       └── mgmt/           # Management protobuf types
│   ├── config/                 # Configuration
│   ├── secure/                 # Cryptographic signing & verification
│   ├── anonymize/              # GDPR-compliant data masking
│   ├── transport/              # Transport layer (gRPC, compression)
│   ├── metrics/                # Prometheus metrics
│   ├── hwaccel/                # Hardware acceleration (NVMe, GPU)
│   └── plugin/                 # Plugin system (scoring, threat intel)
│
├── build/                      # Build & deployment
│   ├── docker/                 # Dockerfiles (Ubuntu, Rocky Linux)
│   ├── *.sh                    # Build, deploy, verify scripts
│   └── providapt.toml          # Default configuration
│
├── test/
│   ├── integration/            # Integration tests
│   │   ├── attack-scenarios/   # APT attack simulation
│   │   ├── kernel-test/        # Kernel compatibility tests
│   │   ├── capture_test.go     # Capture tests
│   │   └── ...
│   ├── benchmark/              # Performance benchmarks
│   └── fuzz/                   # Fuzz testing
│
├── docs/                       # Documentation
├── examples/                   # Example code
├── go.mod
└── Makefile
```

## Quick Start

```bash
# Build all v1 components
make v1

# Run tests
make test

# Run APT attack simulation (requires root + eBPF-enabled kernel)
sudo make attack-sim
sudo make verify-capture
```

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
| [Developer Guide](docs/developer/INDEX.md) | API, schema, changelog |
| [Benchmarks](docs/benchmarks/INDEX.md) | Performance data |
| [Compliance](docs/compliance/INDEX.md) | Security, privacy |

## Requirements

- Linux kernel 5.8+ (5.11+ for LSM BPF)
- BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- clang 12+, llvm-strip
- libbpf 1.0+
- Go 1.22+

## License

Apache 2.0
