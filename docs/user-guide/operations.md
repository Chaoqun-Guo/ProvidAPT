# Operations & Monitoring Guide

**Metrics, Backpressure, Backup, and Logging**

---

## 1. Monitoring Metrics

### 1.1 Key Performance Indicators

| Metric | Source | Warning | Critical | Description |
|--------|--------|---------|----------|-------------|
| `providapt_events_total` | Ring buffer count | — | — | Total events ingested |
| `providapt_events_dropped` | Ring buffer | >0 | >100 | Lost events (backpressure) |
| `providapt_cpu_percent` | /proc/stat | >50% | >80% | Agent CPU usage |
| `providapt_memory_rss_bytes` | /proc/status | >70% limit | >85% limit | Agent RSS |
| `providapt_graph_nodes` | Graph stats | — | — | Total nodes in DAG |
| `providapt_graph_edges` | Graph stats | — | — | Total edges in graph |
| `providapt_scan_duration_ms` | Analyzer scan | >5s | >30s | Time per analysis cycle |
| `providapt_alert_count` | Alert channel | — | — | Alerts generated |
| `providapt_stitch_edges` | Central server | — | — | Cross-host stitch edges |
| `providapt_ringbuf_usage` | bpftool | >50% | >80% | Ring buffer saturation |

### 1.2 Prometheus Integration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'providapt'
    static_configs:
      - targets: ['localhost:8722']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

Export via the test harness `/all-stats` endpoint, or implement a dedicated `/metrics` endpoint:

```bash
# Quick check
curl -s http://localhost:8722/all-stats | jq '.'
```

### 1.3 Grafana Dashboard Variables

```
providapt_events_total{job="providapt"}
providapt_memory_rss_bytes{job="providapt"}
providapt_cpu_percent{job="providapt"}
```

---

## 2. Backpressure Configuration

### 2.1 Pressure Watermarks

The `PressureMonitor` watches Go runtime memory metrics and triggers actions at three thresholds:

| Watermark | Fraction | Action |
|-----------|----------|--------|
| Low | 50% | Log memory stats |
| Mid | 70% | Force LRU eviction (256 coldest nodes) + DB flush |
| High | 85% | Request ingestion slow-down via channel signal |

### 2.2 Configuration

```go
// In pipeline configuration
cfg := &pipeline.Config{
    MaxMemoryMB: 4096,    // 4 GB soft limit
    MergeWindow: 5 * time.Second,
    MaxCacheSize: 8192,
}
```

To adjust sensitivity, modify the watermarks in `backpressure.go`:

```go
lowMark:  0.50   // Start logging
midMark:  0.70   // Force eviction + flush
highMark: 0.85   // Slow down ingestion
```

### 2.3 Monitoring Backpressure

```bash
# Check agent log for pressure events
grep "pressure" /var/log/providapt/providapt.log

# Expected output:
# [pressure] memory: 2048 MB / 4096 MB (50%)
# [pressure] MID — evicting cold nodes
# [pressure] HIGH — forcing flush + slow-down

# Check ring buffer drops (requires bpftool)
bpftool map show | grep ringbuf
```

### 2.4 Tuning Guidelines

| Scenario | MaxMemoryMB | Cache Size | Merge Window |
|----------|-------------|------------|--------------|
| Light (dev/test) | 1024 | 2048 | 10s |
| Normal (production) | 4096 | 8192 | 5s |
| Heavy (high-throughput) | 8192 | 16384 | 2s |
| Memory-constrained | 512 | 1024 | 10s |

---

## 3. Backup & Recovery

### 3.1 Data Directory Structure

```
/var/lib/providapt/
├── store/                    # Pebble database
│   ├── *.sst                # SST files (sorted string tables)
│   ├── MANIFEST-*           # Database manifest
│   ├── OPTIONS-*            # Database options
│   ├── WAL-*                # Write-ahead logs
│   └── LOCK                 # Database lock
├── hashcache/               # Transport dedup cache (optional)
├── lowprio/                 # Low-priority event queue (optional)
└── anchors/                 # Merkle tree anchors
```

### 3.2 Backup Procedure

```bash
#!/bin/bash
# Daily backup script

BACKUP_DIR="/backup/providapt/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# 1. Flush in-memory data
curl -X POST http://localhost:8722/admin/flush

# 2. Create Pebble checkpoint (consistent snapshot)
# (In production: use Pebble's Checkpoint API)

# 3. Copy data directory
cp -a /var/lib/providapt/store "$BACKUP_DIR/store"

# 4. Copy configuration
cp -a /etc/providapt "$BACKUP_DIR/etc"

# 5. Compress
tar czf "${BACKUP_DIR}.tar.gz" "$BACKUP_DIR"

# 6. Upload to remote storage (optional)
aws s3 cp "${BACKUP_DIR}.tar.gz" s3://providapt-backups/

# Cleanup: keep 30 days
find /backup/providapt/ -name "*.tar.gz" -mtime +30 -delete
```

### 3.3 Recovery

```bash
# Stop the daemon
providaptctl -stop

# Restore from backup
tar xzf /backup/providapt/20250101.tar.gz -C /
cp -a /backup/providapt/20250101/store/* /var/lib/providapt/store/

# Restart
providaptd
```

### 3.4 Integrity Verification

```bash
# Run verification tool
providapt-verify -data /var/lib/providapt/store -verbose

# Check Merkle tree anchors
providapt-verify -data /var/lib/providapt/store -output /tmp/verification.txt
```

---

## 4. Logging

### 4.1 Log Configuration

```toml
# /etc/providapt/providapt.toml
[logging]
level = "info"                 # debug | info | warn | error
path = "/var/log/providapt/"
max_size_mb = 100
max_backups = 7
max_age_days = 30
compress = true
```

### 4.2 Audit Log

ProvidAPT includes a persistent audit logging framework that records security events, administrative actions, system events, and integrity issues in NDJSON format.

#### Audit Event Categories

| Category | Severity | Typical Events |
|----------|----------|---------------|
| `security` | CRITICAL / WARNING | Honeypot token triggers, tamper detection, policy violations |
| `admin` | INFO | Daemon stop/restart, data purge, config changes |
| `system` | INFO | Daemon startup/shutdown, sanity check failures |
| `integrity` | WARNING | eBPF program loss, CO-RE fallback, map inconsistencies |

#### Audit Log Location

```
/var/log/providapt/
└── audit.ndjson        # Newline-delimited JSON, rotated by logrotate
```

Each entry contains: `id` (UUID), `timestamp`, `category`, `severity`, `message`, `source` (module name), and optional `details`.

#### Querying Audit Logs

```bash
# Show recent 50 entries
providaptctl -audit

# Filter by security events
providaptctl -audit -audit-cat=security

# Last 7 days
providaptctl -audit -audit-since=7d

# JSON output
providaptctl -audit -audit-cat=admin -json
```

#### Audit Points

| Source Module | Events Logged |
|--------------|---------------|
| Daemon (`main.go`) | Startup, shutdown |
| CLI (`providaptctl`) | Stop, restart, purge operations |
| Self-Heal (`selfheal.go`) | eBPF program reload, integrity check failures |
| Deception (`freeze.go`) | Honeypot trigger events |
| Loader (`loader.go`) | CO-RE fallback activation |

### 4.3 Log Categories

| Component | Prefix | Typical Volume |
|-----------|--------|---------------|
| Pipeline | `[pipeline]` | High (every event) |
| Analyzer | `[analyzer]` | Low (per scan cycle) |
| Pressure | `[pressure]` | Very low (only on pressure) |
| Transport | `[transport]` | Low (per batch) |
| GraphSketch | `[graphsketch]` | Low (per upload) |
| Stitch | `[stitch]` | Low (per cross-host match) |
| Deception | `[deception]` | Very low (on trigger) |
| Supply Chain | `[supplychain]` | Low (per package install) |

### 4.3 Log Analysis

```bash
# Monitor scan cycles
tail -f /var/log/providapt/providapt.log | grep "scan complete"

# Watch for anomalies
tail -f /var/log/providapt/providapt.log | grep -E "ANOMALY|CRITICAL|HONEYPOT|SUPPLY_CHAIN"

# Check for errors
grep -E "error|ERROR|panic" /var/log/providapt/providapt.log

# Count event types
grep "event_type" /var/log/providapt/providapt.log | sort | uniq -c
```

---

## 5. Troubleshooting

### 5.1 Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| eBPF load failed | BTF not available | Install `linux-image-$(uname -r)-dbg` |
| No events ingested | LSM not configured | Add `bpf` to kernel cmdline LSM list |
| High memory usage | Cache too large | Reduce `max_cache_size` in config |
| Ring buffer drops | Event overload | Increase `RINGBUF_SIZE` or enable dedup |
| gRPC connection refused | mTLS cert expired | Regenerate certificates |
| CGroup freeze fails | cgroup v2 not mounted | `mount -t cgroup2 none /sys/fs/cgroup` |

### 5.2 Debug Commands

```bash
# Check eBPF program status
bpftool prog list | grep -E "providapt|lsm|tracepoint"

# Check ring buffer usage
bpftool map list | grep ringbuf

# Check kernel config for eBPF
zgrep BPF /proc/config.gz

# Live event stream
bpftool prog tracelog

# Memory profiling
pprof http://localhost:8722/debug/pprof/heap
```
