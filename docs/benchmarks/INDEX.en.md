# Performance Benchmarks

This section provides performance test data and analysis for ProvidAPT in various environments.

## Documents

| Document | Description |
| --- | --- |
| [benchmark-report.md](benchmark-report.md) | Multi-kernel performance benchmark report (event throughput, CPU/memory overhead) |

## Key Metrics Summary

| Metric | Typical Value | Notes |
| --- | --- | --- |
| Event Throughput | 50K - 150K ops/s | Depends on BPF Ring Buffer size and kernel version |
| Avg Latency | < 5 µs (eBPF) | eBPF to userspace delivery latency |
| CPU Overhead | 1-3% | Single core 2.4GHz, 100K ops/s scenario |
| Memory Overhead | ~200 MB | Includes LRU cache + Pebble storage engine |

## Methodology

All benchmarks are based on the automated test framework under `test/benchmark/`, supporting configurable event rates and load patterns.
