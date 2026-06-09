# Performance Benchmark Report

**ProvidAPT** | Overhead analysis under high-frequency syscall load

## 1. Executive Summary

ProvidAPT's eBPF-based event collection adds measurable but controlled overhead. Under heavy load, kernel-side aggregation significantly reduces CPU and memory pressure compared with sending every event upstream.

| Metric | Without Agent | With Agent (Aggregated) | Overhead |
|--------|---------------|--------------------------|----------|
| CPU (File I/O heavy) | 5.2% | 7.8% | +2.6% |
| CPU (Thread heavy) | 8.1% | 12.3% | +4.2% |
| Memory (steady) | N/A | 85 MB | N/A |
| Memory (peak) | N/A | 142 MB | N/A |
| Event throughput | N/A | 52,000 evt/s | N/A |
| Pebble write latency | N/A | 410 ?s/batch | N/A |

## 2. Test Configuration

### Hardware

| Component | Specification |
|-----------|---------------|
| CPU | Intel Xeon Gold 6338 @ 2.0 GHz (32 cores) |
| Memory | 128 GB DDR4 |
| Disk | NVMe SSD 3.5 GB/s sequential |
| Kernel | Linux 6.2.0-36-generic |

### Software

| Component | Version |
|-----------|---------|
| ProvidAPT | `v1.2.1` |
| Go | `1.22` |
| eBPF | CO-RE with BTF |
| Pebble | `v1.1.1` |
| sysbench | `1.0.20` |

## 3. Performance Tables

### File I/O

| Scenario | Load | CPU Avg | CPU Max | Mem Avg | Mem Max |
|----------|------|---------|---------|---------|---------|
| Baseline | light | 2.1% | 3.5% | N/A | N/A |
| Baseline | medium | 3.8% | 5.9% | N/A | N/A |
| Baseline | heavy | 5.2% | 8.1% | N/A | N/A |
| Agent + Aggregation | light | 3.4% | 5.2% | 42 MB | 58 MB |
| Agent + Aggregation | medium | 5.6% | 8.7% | 67 MB | 89 MB |
| Agent + Aggregation | heavy | 7.8% | 11.2% | 85 MB | 132 MB |
| Agent No Aggregation | light | 5.1% | 8.3% | 51 MB | 72 MB |
| Agent No Aggregation | medium | 9.2% | 14.1% | 89 MB | 124 MB |
| Agent No Aggregation | heavy | 14.6% | 21.3% | 142 MB | 198 MB |

### Thread and Process Creation

| Scenario | Load | CPU Avg | CPU Max | Mem Avg | Mem Max |
|----------|------|---------|---------|---------|---------|
| Baseline | light | 3.5% | 5.1% | N/A | N/A |
| Baseline | medium | 5.8% | 8.9% | N/A | N/A |
| Baseline | heavy | 8.1% | 12.4% | N/A | N/A |
| Agent + Aggregation | light | 5.2% | 7.8% | 38 MB | 52 MB |
| Agent + Aggregation | medium | 8.4% | 12.3% | 61 MB | 84 MB |
| Agent + Aggregation | heavy | 12.3% | 17.6% | 92 MB | 142 MB |
| Agent No Aggregation | light | 7.8% | 11.2% | 47 MB | 68 MB |
| Agent No Aggregation | medium | 13.5% | 19.8% | 78 MB | 115 MB |
| Agent No Aggregation | heavy | 19.2% | 28.4% | 128 MB | 187 MB |

## 4. Recommendations

- Keep kernel aggregation enabled in production
- Use SSD storage for the Pebble data directory
- Monitor ring-buffer usage and dropped-event counters
- Avoid verbose debug logging under sustained high load
