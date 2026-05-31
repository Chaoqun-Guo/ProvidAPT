# Performance Benchmark Report

**ProvidAPT v2.2** | Overhead Analysis Under High-Frequency Syscall Load

---

## 1. Executive Summary

ProvidAPT's eBPF-based event collection adds minimal overhead to normal system operation. Under heavy syscall load, the kernel-side aggregation (dedup + adaptive sampling) reduces CPU overhead by **30-50%** compared to reporting every event.

| Metric | Without Agent | With Agent (Aggregated) | Overhead |
|--------|--------------|------------------------|----------|
| CPU (FileIO heavy) | 5.2% | 7.8% | +2.6% |
| CPU (Thread heavy) | 8.1% | 12.3% | +4.2% |
| Memory (steady) | — | 85 MB | — |
| Memory (peak) | — | 142 MB | — |
| Event throughput | — | 52,000 evt/s | — |
| RocksDB write latency | — | 410 µs/batch | — |

## 2. Test Configuration

### 2.1 Hardware

| Component | Specification |
|-----------|---------------|
| CPU | Intel Xeon Gold 6338 @ 2.0 GHz (32 cores) |
| Memory | 128 GB DDR4 |
| Disk | NVMe SSD 3.5 GB/s sequential |
| Kernel | Linux 6.2.0-36-generic (Ubuntu 22.04) |

### 2.2 Software

| Component | Version |
|-----------|---------|
| ProvidAPT | v2.2 |
| Go | 1.22 |
| eBPF | CO-RE with BTF |
| Pebble | v1.1.1 |
| sysbench | 1.0.20 |

## 3. Performance Tables

### 3.1 FileIO (Random Read/Write)

| Scenario | Load | CPU Avg | CPU Max | Mem Avg | Mem Max |
|----------|------|---------|---------|---------|---------|
| Baseline | light | 2.1% | 3.5% | — | — |
| Baseline | medium | 3.8% | 5.9% | — | — |
| Baseline | heavy | 5.2% | 8.1% | — | — |
| Agent + Aggregation | light | 3.4% | 5.2% | 42 MB | 58 MB |
| Agent + Aggregation | medium | 5.6% | 8.7% | 67 MB | 89 MB |
| Agent + Aggregation | heavy | 7.8% | 11.2% | 85 MB | 132 MB |
| Agent No Aggregation | light | 5.1% | 8.3% | 51 MB | 72 MB |
| Agent No Aggregation | medium | 9.2% | 14.1% | 89 MB | 124 MB |
| Agent No Aggregation | heavy | 14.6% | 21.3% | 142 MB | 198 MB |

### 3.2 Thread/Process (Thread Creation)

| Scenario | Load | CPU Avg | CPU Max | Mem Avg | Mem Max |
|----------|------|---------|---------|---------|---------|
| Baseline | light | 3.5% | 5.1% | — | — |
| Baseline | medium | 5.8% | 8.9% | — | — |
| Baseline | heavy | 8.1% | 12.4% | — | — |
| Agent + Aggregation | light | 5.2% | 7.8% | 38 MB | 52 MB |
| Agent + Aggregation | medium | 8.4% | 12.3% | 61 MB | 84 MB |
| Agent + Aggregation | heavy | 12.3% | 17.6% | 92 MB | 142 MB |
| Agent No Aggregation | light | 7.8% | 11.2% | 47 MB | 68 MB |
| Agent No Aggregation | medium | 13.5% | 19.8% | 78 MB | 115 MB |
| Agent No Aggregation | heavy | 19.2% | 28.4% | 128 MB | 187 MB |

## 4. Aggregation Overhead Analysis

### 4.1 Kernel-Side Dedup Savings

| Load | Events/sec (raw) | After Dedup | Reduction |
|------|-----------------|-------------|-----------|
| FileIO light | 8,200 | 1,340 | 83.7% |
| FileIO medium | 22,500 | 3,150 | 86.0% |
| FileIO heavy | 44,000 | 5,720 | 87.0% |
| Threads light | 15,000 | 2,800 | 81.3% |
| Threads medium | 35,000 | 5,950 | 83.0% |
| Threads heavy | 62,000 | 9,920 | 84.0% |

### 4.2 CPU Overhead Comparison

```
Load: FileIO heavy
                          0%     5%     10%    15%    20%    25%
Baseline (no agent)       ████
Agent + Aggregation       ██████
Agent No Aggregation      █████████████

Load: Threads heavy
                          0%     5%     10%    15%    20%    25%
Baseline (no agent)       ██████
Agent + Aggregation       ██████████
Agent No Aggregation      ████████████████
```

## 5. Backpressure & Loss

| Watermark | Events/sec | Memory | Action | Duration |
|-----------|------------|--------|--------|----------|
| <50% | <25,000 | <2048 MB | None | — |
| 50-70% | 25,000-40,000 | 2048-2867 MB | Logging | — |
| 70-85% | 40,000-55,000 | 2867-3482 MB | Eviction + flush | <500ms |
| >85% | >55,000 | >3482 MB | Slow ingestion | Variable |

**Loss rate**: <0.01% under normal load, <0.5% under peak sustained load with backpressure engaged.

## 6. RocksDB Write Latency

| Batch Size | Latency (µs) | Throughput (ops/s) |
|-----------|-------------|-------------------|
| 50 | 185 | 270,000 |
| 100 | 290 | 345,000 |
| 200 | 410 | 488,000 |
| 500 | 890 | 562,000 |

## 7. Recommendations

1. **Enable kernel aggregation** (default) for all production deployments
2. **Set memory limit** to 50-70% of available system RAM for the agent
3. **Monitor ring buffer usage** via bpftool; increase `RINGBUF_SIZE` if drops > 0.1%
4. **Use SSD storage** for Pebble database — HDD latency increases write times 5-10×
5. **Disable verbose mode** in production — debug logging increases IO overhead by ~15%
