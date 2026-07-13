# ProvidAPT Performance Optimization Guide

This guide summarizes practical tuning options for benchmark and load-test environments.

## Pebble Compression

ProvidAPT stores high-volume edge data in Pebble. The default Snappy compression is fast, but Zstd can reduce disk usage for colder levels.

| Level | Recommended Compression | Rationale |
| --- | --- | --- |
| L0 | None | L0 files are small; compression can add write latency. |
| L1 | Zstd level 3 | Edge metadata compresses well because paths and IDs repeat frequently. |
| L2+ | Zstd level 6 | Colder data benefits from higher compression ratios. |

Expected impact:

- 40%-60% lower disk usage for edge-heavy workloads.
- Lower write amplification on long-running test data sets.
- Slightly higher read amplification for cold queries.

## Block Size

For small edge records, smaller Pebble blocks can improve random-read behavior:

```go
opts.Levels[i].BlockSize = 16 << 10 // 16 KB blocks
```

## Edge Encoding

JSON is convenient for inspection, but binary encoding can reduce CPU and storage overhead.

| Encoding | Typical Edge Size | Encode Cost | Decode Cost |
| --- | --- | --- | --- |
| JSON | ~250 B | ~500 ns | ~400 ns |
| Protocol Buffers | ~80 B | ~100 ns | ~80 ns |
| Custom binary | ~60 B | ~30 ns | ~30 ns |

## eBPF Filtering

For high-load benchmarks, reduce ring-buffer pressure by filtering in the kernel:

- Capture only sensitive path prefixes such as `/etc`, `/home`, `/root`, `/tmp`, and `/var/log`.
- Track selected PIDs for focused command monitoring.
- Use hot-path bypass lists for high-interest paths that should not be sampled away.
