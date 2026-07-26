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

PostgreSQL production drill:

```bash
export PROVIDAPT_DATABASE_DSN='postgres://providapt:<password>@postgres.example.com:5432/providapt?sslmode=require'
export PROVIDAPT_RESTORE_DSN='postgres://providapt:<password>@restore.example.com:5432/providapt_restore?sslmode=require'
make ops-postgres-drill
```

The target writes `build/postgres/providapt-control-plane.sql`, restores it to
the optional staging DSN, and runs a sanity query. Use a staging database, not
the production DSN, for `PROVIDAPT_RESTORE_DSN`.
It also writes `build/postgres/postgres-drill.json` and
`build/postgres/postgres-drill.md` with redacted DSNs, backup size, restore
status, schema-table verification, and PostgreSQL client tool versions.

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

CLI wrapper:

```bash
export PROVIDAPT_SERVER_URL=http://<server>:18080
make ops-fleet-list
bash scripts/ops/fleet-lifecycle.sh --server "$PROVIDAPT_SERVER_URL" \
  action --agent agent-a,agent-b --state quarantined --note "incident containment"
```

Common lifecycle transitions:

| Transition | Use Case |
| --- | --- |
| `approved` | host identity reviewed and allowed to receive policy |
| `quarantined` | host is under investigation; telemetry remains visible |
| `revoked` | host is decommissioned, stolen, or should no longer participate |

## 7. Secret and TLS Operations

Generate a customer-fillable secret template:

```bash
make ops-secret-template
make ops-secret-validate SECRET_ENV=/secure/path/providapt.secrets.env
```

The generated `build/providapt.secrets.env.example` is a template only. Replace
all placeholders through the customer's secret manager or deployment pipeline,
then validate the filled file before wiring it into systemd, Docker Compose, or
Kubernetes. See `docs/getting-started/secret-management.md` for deployment
patterns.

Check certificate expiry:

```bash
make ops-tls-bootstrap \
  TLS_OUT=build/tls \
  TLS_SERVER_CN=cp-0.example.com \
  TLS_SERVER_SAN="DNS:cp-0.example.com,IP:192.168.150.132" \
  TLS_AGENT_CNS="ubuntu-129,centos-131"

make ops-tls-check CERTS="/etc/providapt/tls/server.crt /etc/providapt/tls/agent.crt"
```

`ops-tls-bootstrap` writes a CA, server certificate, one certificate per agent
CN, and `manifest.json`. Existing leaf cert/key files are backed up with a
timestamp suffix before replacement. Copy the generated paths into
`tls.*`, `telemetry.*`, and `policy.*` configuration fields, restart or reload
the affected service, then verify the dashboard plus telemetry endpoints before
closing the change. Treat certificates inside the warning window as an
operational change request.

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

Compliance report bundle and SIEM verification:

```bash
curl -X POST http://<server>:18080/api/v1/control/compliance \
  -H "Content-Type: application/json" \
  -d '{"action":"generate_report","format":"bundle"}'

export PROVIDAPT_SERVER_URL=http://<server>:18080
make ops-siem-verify
```

The report bundle returns both JSON and HTML artifacts. Use JSON for automated
release evidence checks and HTML for operator review or customer handoff.
