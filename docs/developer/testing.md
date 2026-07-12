# Testing Guide

## Quick Start

```bash
# Run all core unit tests with coverage
make test-core

# Run with race detection
make test-race

# View coverage summary
make coverage

# Generate HTML coverage report
make coverage-html

# Run fuzz tests (10s per target)
make fuzz-short
```

## Coverage

### Project-Wide Threshold

Current total coverage: **~61%** (as of v1.2.2). CI enforces a minimum of **20%** total coverage.

### Running Coverage Locally

```bash
make coverage          # Text summary 鈫?build/coverage/coverage.txt
make coverage-html     # HTML report 鈫?build/coverage/coverage.html
```

### Quality Gate

The CI pipeline checks total coverage against a threshold (currently 20%). If coverage drops below the threshold, the build fails. The threshold is raised incrementally as coverage improves.

# Testing Guide

## Test Organization

```text
test/
├── integration/                 # Integration-level tests
│   ├── attack-scenarios/        # APT attack simulation (bash)
│   │   ├── attack_sim.sh        # 5-phase APT attack simulation
│   │   ├── privilege-escalation.sh
│   │   ├── lateral-movement.sh
│   │   ├── persistence.sh
│   │   ├── verify_capture.sh
│   │   └── run_e2e.sh
│   ├── kernel-test/             # Kernel compatibility test framework
│   │   ├── Dockerfile
│   │   ├── images.yml           # Kernel version matrix (5.4-6.8)
│   │   ├── run_tests.sh
│   │   ├── generate_report.py
│   │   ├── stress_test.go
│   │   └── config.yml
│   ├── integration_test.py      # Multi-host SSH integration
│   ├── full_validation.sh       # Pipeline validation
│   ├── final_check.sh           # Kubernetes and self-healing check
│   ├── cluster_test.py          # Multi-host cluster test
│   ├── supply_chain_test.sh     # Supply-chain test
│   └── *_test.go                # Go integration tests
├── benchmark/                   # Performance benchmarks
│   ├── eventgen.go
│   ├── eventgen_test.go
│   ├── latency_test.go
│   ├── pipeline_bench_test.go
│   └── run_benchmark.sh
└── fuzz/                        # Fuzz testing targets
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

# Verify real eBPF loader startup and object override
sudo make loader-smoke

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
| Loader Smoke | `test/integration/loader_smoke.sh` | root, eBPF, clang | Real loader startup + path override |
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

1. **Fast path** (every commit): `make test` + `make ext-test` + coverage collection
2. **Integration path** (nightly): Full integration suite in Docker
3. **Kernel path** (weekly): Kernel compatibility matrix
4. **Manual loader path**: GitHub Actions `CI` workflow `loader smoke (manual)` job
5. **Release path**: All tests + benchmarks + attack simulations

### Coverage in CI

Each `go test` invocation in CI includes `-coverprofile` and `-covermode=atomic`. After all tests run, profiles are merged into a single report at `build/coverage/merged.out`.

A **quality gate** checks that total coverage meets the threshold (currently 20%). Coverage artifacts are uploaded for manual download and review.

The `loader smoke (manual)` job is exposed through `workflow_dispatch` so maintainers can validate the real eBPF loader on a Linux runner without making every PR depend on kernel/runtime support.

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
