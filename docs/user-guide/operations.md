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
curl "http://<server>:18080/api/v1/control/fleet?group=prod&tag=linux"
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
make ops-fleet-action \
  FLEET_AGENTS=agent-a,agent-b \
  FLEET_STATE=approved \
  FLEET_NOTE="host identity reviewed"
make ops-fleet-plan FLEET_OPERATION=cert-rotation FLEET_GROUP=prod FLEET_TAG=linux
```

Common lifecycle transitions:

| Transition | Use Case |
| --- | --- |
| `approved` | host identity reviewed and allowed to receive policy |
| `quarantined` | host is under investigation; telemetry remains visible |
| `revoked` | host is decommissioned, stolen, or should no longer participate |

Use `make ops-fleet-plan` before high-impact lifecycle work. It writes JSON and
Markdown dry-run evidence under `build/fleet/` for certificate rotation,
quarantine, and decommissioning.
Use `make ops-fleet-action` after review to apply enrollment transitions and
capture per-agent JSON/Markdown action evidence.

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

Generate production foundation readiness evidence after secrets, TLS, PostgreSQL, and
fleet checks are available:

```bash
make production-readiness-gate \
  SECRET_MANIFEST=build/secrets/secret-backend-manifest.json \
  TLS_MANIFEST=build/tls/manifest.json \
  POSTGRES_REPORT=build/postgres/postgres-drill.json \
  PROVIDAPT_SERVER_URL=http://<server>:18080
```

The report blocks when any required secret backend artifact is missing,
including Vault policy/loader/config outputs, TLS rotation material is
incomplete, PostgreSQL backup evidence is missing, or fleet reports are stale.

Validate install handoff assets before packaging or customer deployment:

```bash
make install-delivery-check \
  PROVIDAPT_CONFIG=examples/config/providapt.production.yaml \
  OUT_DIR=build/install-delivery
```

Use `STRICT_BINARIES=1` after `make build-core` or package extraction to require
the expected binaries in `build/bin`. The report checks installer-adjacent
binaries, production config, systemd service wiring, environment defaults, and
required handoff documents.

Validate production observability assets:

```bash
make observability-pack-check \
  PROMETHEUS_CONFIG=scripts/docker/prometheus.yml \
  PROMETHEUS_ALERTS=scripts/docker/providapt_alerts.yml \
  GRAFANA_DASHBOARD=scripts/docker/providapt_dashboard.json
```

When a control plane is running, add `PROVIDAPT_SERVER_URL=http://<server>:18080`
to verify live `/metrics` and `/api/v1/status`. The report checks Prometheus
scrape config, critical alert rules, Grafana dashboard structure, and required
metrics.

Validate production security hardening:

```bash
make security-hardening-gate \
  PROVIDAPT_CONFIG=examples/config/providapt.production.yaml \
  RBAC_AUDIT=build/rbac/rbac-audit.json \
  OUT_DIR=build/security-hardening
```

The gate verifies production config controls, systemd sandbox markers, risky
environment bypass defaults, and optional RBAC audit evidence. eBPF-related
systemd relaxations are reported as warnings so a release owner can explicitly
approve them.

Check certificate expiry:

```bash
make ops-tls-bootstrap \
  TLS_OUT=build/tls \
  TLS_SERVER_CN=cp-0.example.com \
  TLS_SERVER_SAN="DNS:cp-0.example.com,DNS:vm-ubuntu-master.<TAILSCALE_DOMAIN>" \
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

Plan scheduled executive or compliance report generation:

```bash
make scheduled-report-plan \
  REPORT_NAME=compliance \
  REPORT_CADENCE=1w \
  REPORT_FORMATS=markdown,json,bundle \
  REPORT_RECIPIENTS=secops@example.com,compliance@example.com \
  OUT_DIR=build/reports
```

The generated plan records the report command, retention budget, systemd timer
metadata, and Kubernetes CronJob schedule. Treat it as the approval artifact
before wiring the schedule into customer automation.

## 8. Operations Readiness

After constrained VM deployment, capture deployment evidence from the control
plane:

```bash
make verify-vm-fleet \
  PROVIDAPT_SERVER_URL=http://<server>:18080 \
  EXPECTED_COMMIT="$(git rev-parse --short HEAD)"
```

The report verifies dashboard cluster actions, graph export, alert workflow
access, agent health, and telemetry freshness. Store the JSON/Markdown outputs
with the deployment handoff record.

Aggregate enterprise delivery evidence after release gates, secret backend
handoff, PostgreSQL drills, detection quality, RBAC audit, and scheduled report
plan artifacts are generated:

```bash
make enterprise-readiness \
  RBAC_AUDIT_JSON=build/rbac/rbac-audit.json \
  REPORT_PLAN_JSON=build/reports/scheduled-report-plan.json
```

Evaluate long-duration soak evidence against CPU, memory, disk, duration,
and dropped-event budgets:

```bash
export SOAK_STARTED_AT_EPOCH="$(date +%s)"
make soak-sample \
  STATUS_URL=http://<server>:18080/api/v1/status \
  SOAK_STARTED_AT_EPOCH="$SOAK_STARTED_AT_EPOCH" \
  OUT=build/performance/soak-samples.json

make soak-readiness \
  SOAK_SAMPLES=build/performance/soak-samples.json \
  SOAK_MIN_HOURS=24 \
  SOAK_MAX_MEMORY_MB=512 \
  SOAK_MAX_DISK_MB=4096
```

Both commands write Markdown and JSON artifacts under `build/` for release
review, support handoff, and customer readiness meetings.

Run `make soak-sample` on a schedule during 24-72 hour validation windows. Keep
the generated `soak-samples.json` with the final `soak-readiness.json` and
`soak-readiness.md` evidence.

Close operations readiness with the operations readiness gate:

```bash
make operations-readiness-gate \
  PRODUCTION_READINESS_GATE=build/production-readiness/production-readiness-gate.json \
  ML_READINESS_GATE=build/ml-readiness/ml-readiness-gate.json \
  FLEET_VERIFICATION=build/deploy/vm-fleet-verification.json \
  SOAK_READINESS=build/performance/soak-readiness.json \
  UPGRADE_ROLLOUT=build/upgrade/rollout-plan.json \
  SIEM_VERIFY=build/siem/siem-verification.json \
  RBAC_AUDIT=build/rbac/rbac-audit.json \
  INSTALL_DELIVERY_CHECK=build/install-delivery/install-delivery-check.json \
  OBSERVABILITY_PACK_CHECK=build/observability/observability-pack-check.json \
  SECURITY_HARDENING_GATE=build/security-hardening/security-hardening-gate.json
```

The operations readiness gate blocks when production foundation, detection/ML evidence, fleet
health, soak stability, upgrade rollout, SIEM/SOAR delivery, RBAC audit,
installation handoff, observability pack, or security hardening evidence is
missing or failed.

For large investigations, the dashboard graph summary groups nodes into
clusters and high-degree hubs. Use `Inspect` to view a collapsed cluster,
`Backward` or `Forward` to open a focused trace for a node, and `Export Cluster`
to download a filtered graph JSON for offline layout or model-training review.

Plan staged upgrades with canary, pause/resume gates, waves, and rollback order:

```bash
make upgrade-rollout-plan \
  FLEET_JSON=build/fleet/fleet.json \
  TARGET_VERSION=v1.2.3 \
  CANARY_PERCENT=10 \
  MAX_BATCH_SIZE=25
```

Generate a first-run onboarding bundle for a new customer or lab deployment:

```bash
make onboarding-wizard \
  OUT_DIR=build/onboarding \
  POSTGRES_DSN='postgres://providapt:<password>@postgres:5432/providapt?sslmode=require'
```

The onboarding bundle includes a production-oriented starter config, checklist,
and manifest that can be attached to customer handoff evidence.

## 9. Commercialization Readiness

Validate plugin release evidence before enabling customer-specific detection,
scoring, threat-intelligence, or enrichment extensions:

```bash
make plugin-release-gate \
  PLUGIN_MANIFEST=plugins/example/plugin.json \
  PLUGIN_SIGNATURE=plugins/example/plugin.json.sig
```

Close commercialization readiness with the commercialization readiness gate:

```bash
make commercialization-readiness-gate \
  OPERATIONS_READINESS_GATE=build/operations-readiness/operations-readiness-gate.json \
  ENTERPRISE_READINESS=build/enterprise-readiness.json \
  ONBOARDING_MANIFEST=build/onboarding/onboarding-manifest.json \
  PLUGIN_GATE=build/plugins/plugin-release-gate.json \
  EXTERNAL_APPROVAL=docs/project/external-approval-request-v1.2.3-rc.1.md
```

The commercialization readiness gate verifies customer handoff documentation, onboarding artifacts,
external approval evidence, enterprise readiness, and optional plugin release
gates. Missing plugin evidence is a warning when no plugins are shipped; failed
plugin evidence blocks release.
