# Testing Guide

## Test Organization

```
test/
├── integration/              # Integration-level tests
│   ├── attack-scenarios/     # APT attack simulation (bash)
│   │   ├── attack_sim.sh           # 5-phase APT attack simulation
│   │   ├── privilege-escalation.sh # SUID/sudo/capability abuse
│   │   ├── lateral-movement.sh     # SSH/DNS/curl/SCP movement
│   │   ├── persistence.sh          # Cron/SSH keys/systemd hooks
│   │   ├── verify_capture.sh       # Validate provenance graph
│   │   └── run_e2e.sh              # Full pipeline orchestration
│   │
│   ├── kernel-test/          # Kernel compatibility test framework
│   │   ├── Dockerfile              # Multi-stage test container
│   │   ├── images.yml              # Kernel version matrix (5.4–6.8)
│   │   ├── run_tests.sh            # CO-RE + stress test runner
│   │   ├── generate_report.py      # HTML report generation
│   │   └── stress_test.go          # 10K fork stress test
│   │
│   ├── config.yml            # VM test configuration
│   ├── integration_test.py   # Multi-host SSH integration (3 VMs)
│   ├── full_validation.sh # v2.0 pipeline validation
│   ├── final_check.sh   # v2.1 K8s/self-healing check
│   ├── cluster_test.py  # v2.2 multi-host cluster test
│   ├── supply_chain_test.sh # v2.2 supply chain test
│   └── *_test.go             # Go integration tests
│
├── benchmark/                # Performance benchmarks
│   ├── eventgen.go           # Event generator for load testing
│   ├── eventgen_test.go
│   ├── latency_test.go       # End-to-end latency measurement
│   ├── pipeline_bench_test.go # Pipeline throughput benchmarks
│   └── run_benchmark.sh      # Benchmark runner
│
└── fuzz/                     # Fuzz testing (directory ready)
```

## Running Tests

### Unit Tests (No Root Required)

```bash
# All unit tests
make test

# Version-specific tests
make ext-test     # extended engine/storage/policy
make cluster-test    # cluster/stitcher tests
```

### Integration Tests (Requires Root + eBPF)

```bash
# APT attack simulation (5-phase)
make attack-sim

# Verify provenance graph capture
make verify-capture

# Full end-to-end pipeline
bash test/integration/attack-scenarios/run_e2e.sh
```

### Docker Tests

```bash
# Build test container
make docker-build

# Run Docker with eBPF support
make docker-run

# Inside container: run the kernel test suite
cd /workspace
bash test/integration/kernel-test/run_tests.sh
```

### Performance Benchmarks

```bash
# Run benchmark suite
bash test/benchmark/run_benchmark.sh

# Run specific benchmark
go test -bench=. -benchmem ./test/benchmark/...
```

## Test Types

| Test Type | Location | Requirements | Coverage |
| --------- | -------- | ------------ | -------- |
| Unit | `internal/...` | Go only | Individual packages |
| Integration (Go) | `test/integration/*_test.go` | Go | Cross-package workflows |
| Integration (Shell) | `test/integration/attack-scenarios/` | root, eBPF | APT attack chains |
| Integration (Python) | `test/integration/*.py` | SSH VMs | Multi-host scenarios |
| Kernel | `test/integration/kernel-test/` | Docker, BTF | Kernel compatibility |
| Benchmark | `test/benchmark/` | Go | Performance metrics |

## Writing Tests

### Adding a New Unit Test

Place the test file alongside the package code:
```
internal/engine/provenance/graph_test.go
```

Use standard Go testing patterns:
```go
func TestGraphAddNode(t *testing.T) {
    g := NewGraph()
    n := g.AddNode("process", 100)
    if n == nil {
        t.Fatal("expected node")
    }
}
```

### Adding Integration Tests

Go integration tests go in `test/integration/`:
```go
func TestCapturePipeline(t *testing.T) {
    if os.Getuid() != 0 {
        t.Skip("requires root")
    }
    // test code
}
```

Shell-based attack simulations go in `test/integration/attack-scenarios/` with proper cleanup:
```bash
#!/bin/bash
set -euo pipefail
SIM_TMPDIR=$(mktemp -d)
trap 'rm -rf "$SIM_TMPDIR"' EXIT
```

## CI Integration

The test suite is designed for CI pipelines:

1. **Fast path** (every commit): `make test` + `make ext-test`
2. **Integration path** (nightly): Full integration suite in Docker
3. **Kernel path** (weekly): Kernel compatibility matrix
4. **Release path**: All tests + benchmarks + attack simulations

## Test Configuration

Integration tests use `test/integration/config.yml` for VM configuration:

```yaml
hosts:
  ubuntu:
    ip: 192.168.1.101
    user: root
    key: ~/.ssh/test_key
```

For local testing, these can be overridden via environment variables:
```bash
export TEST_HOST_IP=127.0.0.1
export TEST_HOST_USER=root
```
