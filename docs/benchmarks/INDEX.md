# Benchmarks

This section summarizes ProvidAPT performance test methods and results across representative environments.

## Documents

| Document | Description |
| --- | --- |
| [benchmark-report.md](benchmark-report.md) | Event throughput, latency, CPU, and memory overhead report |

## Key Metrics

| Metric | Typical Value | Notes |
| --- | --- | --- |
| Event throughput | 50K-150K ops/s | Depends on ring-buffer pressure and kernel version |
| Average latency | < 5 us | eBPF-to-userspace delivery latency |
| CPU overhead | 1%-3% | Typical single-host workload |
| Memory overhead | Approximately 200 MB | Includes caches and storage engine |

## Method

Benchmark automation and scenarios are located under `test/benchmark/`.
