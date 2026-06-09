# Operations & Monitoring Guide

**Metrics, Backpressure, Backup, and Logging**

## 1. Monitoring Metrics

| Metric | Source | Warning | Critical | Description |
|--------|--------|---------|----------|-------------|
| `providapt_events_total` | Ring buffer count | N/A | N/A | Total events ingested |
| `providapt_events_dropped` | Ring buffer | `>0` | `>100` | Lost events caused by pressure |
| `providapt_cpu_percent` | `/proc/stat` | `>50%` | `>80%` | Agent CPU usage |
| `providapt_memory_rss_bytes` | `/proc/status` | `>70%` limit | `>85%` limit | Agent RSS |
| `providapt_graph_nodes` | Graph stats | N/A | N/A | Total nodes in DAG |
| `providapt_graph_edges` | Graph stats | N/A | N/A | Total edges in graph |
| `providapt_scan_duration_ms` | Analyzer scan | `>5s` | `>30s` | Time per analysis cycle |
| `providapt_alert_count` | Alert channel | N/A | N/A | Alerts generated |
| `providapt_stitch_edges` | Central server | N/A | N/A | Cross-host stitch edges |
| `providapt_ringbuf_usage` | `bpftool` | `>50%` | `>80%` | Ring-buffer saturation |

## 2. Prometheus Integration

```yaml
scrape_configs:
  - job_name: "providapt"
    static_configs:
      - targets: ["localhost:8722"]
    metrics_path: "/metrics"
    scrape_interval: 15s
```

Quick check:

```bash
curl -s http://localhost:8722/all-stats | jq '.'
```

## 3. Backpressure Watermarks

| Watermark | Fraction | Action |
|-----------|----------|--------|
| Low | 50% | Log memory stats |
| Mid | 70% | Force LRU eviction and flush |
| High | 85% | Request ingestion slow-down |

Expected log lines:

```text
[pressure] memory: 2048 MB / 4096 MB (50%)
[pressure] MID - evicting cold nodes
[pressure] HIGH - forcing flush and slow-down
```

## 4. Backup and Recovery

Recommended data layout:

```text
/var/lib/providapt/
??? store/
??? hashcache/
??? lowprio/
??? anchors/
```

Backup flow:

```bash
providaptctl -stop
tar czf providapt-backup.tar.gz /var/lib/providapt /etc/providapt
```

Restore flow:

```bash
tar xzf providapt-backup.tar.gz -C /
sudo systemctl start providapt
```

## 5. Integrity Verification

```bash
providapt-verify -data /var/lib/providapt/store -verbose
```
