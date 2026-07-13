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
|- store/
|- hashcache/
|- lowprio/
`- anchors/
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

## 6. Server-Side Agent Monitoring

The control plane monitors every reporting agent through the gRPC telemetry
stream and exposes the fleet state in the dashboard and API.

Dashboard:

```text
http://<server>:18080/
```

Fleet APIs:

```bash
curl http://<server>:18080/api/v1/control/overview
curl http://<server>:18080/api/v1/control/ha
curl http://<server>:18080/api/v1/control/fleet
curl "http://<server>:18080/api/v1/control/fleet -> group=prod&tag=linux"
```

Agent status values:

| Status | Meaning |
|--------|---------|
| `HEALTHY` | The server recently received a healthy agent summary |
| `DEGRADED` | The agent reports unhealthy pipeline or store state |
| `STALE` | No summary was received for the stale threshold |
| `OFFLINE` | No summary was received for the offline threshold |

The fleet response includes `last_report_at`, `last_report_age_seconds`, and
`status_reason`, so operators can distinguish a healthy agent from one that has
stopped reporting.

Batch lifecycle operations:

```bash
curl -X POST http://<server>:18080/api/v1/control/fleet \
  -H "Content-Type: application/json" \
  -d '{"agent_ids":["agent-a","agent-b"],"action":"quarantined","note":"incident containment"}'
```

The response reports per-agent success or failure, which makes bulk quarantine,
approval, revocation, and metadata updates safe to automate.

Investigation reports:

```bash
curl "http://<server>:18080/api/v1/investigation/report?pid=1234&direction=backward&depth=5"
curl "http://<server>:18080/api/v1/investigation/report?node=p:1234&direction=forward&format=markdown"
```

The report includes trace scope, risk summary, key observations, timeline nodes,
and provenance relations for audit handoff or incident review.

Policy diff and alert workflow operations:

```bash
curl http://<server>:18080/api/v1/control/policies
curl -X POST http://<server>:18080/api/v1/control/alerts \
  -H "Content-Type: application/json" \
  -d '{"action":"silence","alert_ids":["alert-a","alert-b"],"duration":"30m","note":"maintenance window"}'
```

The dashboard exposes the same flows through `Show Diff`, `Preview Report`,
`Download Markdown`, and bulk alert action buttons.
