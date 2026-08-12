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
environment bypass defaults, and optional RBAC audit evidence. Configuration
checks include API auth keys, restricted CORS origins, REST TLS certificate
paths, TLS rotation settings, encrypted storage, approval workflow, support
bundle redaction, agent telemetry TLS, HTTPS policy pulls, and a production
secret backend (`file` or `vault`). Placeholder API keys or database passwords
are warnings in sample files and must be replaced by customer-approved secret
material before release approval. eBPF-related systemd relaxations are reported
as warnings so a release owner can explicitly approve them.

For release candidates, run strict mode so warnings and missing optional
evidence, including RBAC audit evidence, block the gate:

```bash
make security-hardening-gate \
  STRICT_SECURITY=1 \
  RBAC_AUDIT=build/rbac/rbac-audit.json
```

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

Gate policy approval workflow evidence after RBAC and compliance status are
captured:

```bash
make policy-approval-gate \
  RBAC_AUDIT=build/rbac/rbac-audit.json \
  COMPLIANCE_STATUS=build/compliance/compliance-status.json \
  AUDIT_LOG=build/audit/control-audit.json \
  REQUIRE_APPROVAL_AUDIT=1
```

Gate backup, restore, and cutover evidence:

```bash
make backup-readiness-gate \
  BACKUP_SUMMARY=build/backup/backup-summary.json \
  REQUIRE_BACKUP_RESTORE=1 \
  REQUIRE_BACKUP_CUTOVER=1 \
  REQUIRE_BACKUP_DOWNLOAD=1
```

Gate support bundle redaction and audit evidence:

```bash
make support-bundle-gate \
  SUPPORT_SUMMARY=build/support/support-bundle-summary.json \
  REQUIRE_SUPPORT_ARCHIVE=1 \
  REQUIRE_SUPPORT_REDACTED=1 \
  REQUIRE_SUPPORT_AUDIT=1 \
  REQUIRE_SUPPORT_DOWNLOAD=1
```

Gate runtime deployment diagnostics saved from `/api/v1/status`:

```bash
make deployment-diagnostics-gate \
  STATUS_JSON=build/deploy/status.json \
  REQUIRE_API_AUTH=1 \
  REQUIRE_TLS=1 \
  REQUIRE_STORAGE_ENCRYPTION=1 \
  REQUIRE_POLICY_SYNC=1 \
  REQUIRE_KERNEL_ATTACH=1
```

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

Capture dashboard and Trace Viewer screenshots for visual regression review:

```bash
make visual-regression-snapshots \
  PROVIDAPT_SERVER_URL=http://<server>:18080 \
  ALERT_ID=p:100
```

The helper writes PNG screenshots plus JSON/Markdown manifests under
`build/visual-regression/` for mobile `390x844`, `1366x768`, `1920x1080`,
and ultrawide `2560x1080` viewports. Dashboard captures run DOM overflow
assertions for horizontal document overflow, element bounds, and text overflow.
Trace Viewer captures run browser assertions for rendered SVG presence, layout
mode controls, PNG/SVG/raw export controls, and report links. The manifest also
records coverage by page, viewport, viewport class, and missing default
viewports so release evidence can show whether the full baseline matrix was
captured. The manifest includes a required page/viewport matrix with status,
path, DOM assertion presence, and screenshot hash presence for each Dashboard
and Trace Viewer target. Pass
`BASELINE=build/visual-regression/visual-regression-snapshots.json` to compare
current screenshot hashes against a previous manifest. Baseline comparisons
include a `comparison_summary` with changed, unchanged, new, skipped, and
missing-baseline counts plus focused changed/skipped detail for release review.
Use `DRY_RUN=1` to validate the screenshot plan without launching a browser.
The visual regression gate reports missing required screenshots both as exact
page/viewport pairs and grouped by page and viewport. DOM assertion failures are
also summarized with Dashboard overflow metrics and Trace Viewer missing layout
modes or export controls.

Gate captured screenshot evidence before release:

```bash
make visual-regression-gate \
  VISUAL_REGRESSION_MANIFEST=build/visual-regression/visual-regression-snapshots.json
```

The gate requires captured dashboard and Trace Viewer screenshots for
`390x844`, `1366x768`, `1920x1080`, and `2560x1080`, verifies screenshot files
and hashes are present, and requires passing DOM assertions. Baseline hash changes
block unless `WARN_ON_VISUAL_CHANGED=1` is set for a controlled review. The gate
also writes `visual_evidence_summary` with coverage, required-matrix gaps,
baseline comparison counts, screenshot status, and DOM assertion totals.
Dashboard responsive rules live in the embedded static assets
`pkg/api/static/dashboard.css`, `pkg/api/static/dashboard-responsive.css`, and
`pkg/api/static/dashboard.js`, served at `/assets/dashboard.css`,
`/assets/dashboard-responsive.css`, and `/assets/dashboard.js`. Trace Viewer
styles and behavior live in `pkg/api/static/trace-viewer.css` and
`pkg/api/static/trace-viewer.js`, served at `/assets/trace-viewer.css` and
`/assets/trace-viewer.js`.

Collect real API stress evidence for larger Trace SVGs and layout modes:

```bash
make trace-svg-stress \
  PROVIDAPT_SERVER_URL=http://<server>:18080 \
  MAX_LATENCY_MS=1500 \
  MIN_TRACE_NODES=25
```

When `ALERT_IDS` is omitted, the helper discovers up to three alert IDs from
`/api/v1/control/alerts`; set `TRACE_DISCOVER_LIMIT=N` to adjust this. The
report requests each alert with `tree`, `compact`, `timeline`, and `grouped`
layouts, then records latency, SVG dimensions, byte size, node count, edge
count, folded cluster count, and whether alerts were provided or discovered
under `build/trace-stress/`.

Validate capture/enrichment field coverage from VM or evaluation NDJSON before
training or customer evidence review:

```bash
make capture-enrichment-field-gate \
  EVENTS=build/vm-training/attack_events.ndjson \
  OUT_DIR=build/capture-quality
```

The report checks event type, PID/PPID, UID/GID, command line, executable path,
file pathname, and network tuple coverage, then writes JSON/Markdown evidence
under `build/capture-quality/`.

For release evidence from the three Tailscale-connected VMs, collect real
`providapt-*.ndjson` files over SSH/SCP and run the same field gate:

```bash
make collect-vm-capture-evidence \
  PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave" \
  REMOTE_DIR=/var/log/providapt \
  SSH_TIMEOUT_SECONDS=15 \
  CAPTURE_GATE_TIMEOUT_SECONDS=60 \
  MAX_VM_EVENT_FILES=5 \
  VM_EVENT_LINES=5000 \
  VM_NETWORK_LINES=200 \
  OUT_DIR=build/vm-capture-evidence
```

This command samples the latest VM event files into `build/vm-capture-evidence/`,
also extracts recent `net_*` lines from the same files so network tuple coverage
is exercised, aggregates them into a local evidence directory, and writes
`vm-capture-evidence.json`, `vm-capture-evidence.md`,
`capture-enrichment-field-gate.json`, and
`capture-enrichment-field-gate.md`. Do not commit the copied NDJSON files.

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
  POLICY_APPROVAL_GATE=build/policy-approval/policy-approval-gate.json \
  BACKUP_READINESS_GATE=build/backup/backup-readiness-gate.json \
  SUPPORT_BUNDLE_GATE=build/support/support-bundle-gate.json \
  DEPLOYMENT_DIAGNOSTICS_GATE=build/deploy/deployment-diagnostics-gate.json \
  INSTALL_DELIVERY_CHECK=build/install-delivery/install-delivery-check.json \
  OBSERVABILITY_PACK_CHECK=build/observability/observability-pack-check.json \
  SECURITY_HARDENING_GATE=build/security-hardening/security-hardening-gate.json
```

The operations readiness gate blocks when production foundation, detection/ML
evidence, fleet health, soak stability, upgrade rollout, SIEM/SOAR delivery,
RBAC audit, policy approval, backup readiness, support bundle evidence,
deployment diagnostics, installation handoff, observability pack, visual
regression, capture/enrichment coverage, or security hardening evidence is
missing or failed. Visual regression readiness carries screenshot coverage,
default-matrix completion, baseline change counts, DOM assertion failures, and
missing required screenshot counts from `visual_evidence_summary`.

Close open-source readiness after release gates, operations, enterprise,
model lifecycle, visual baseline, onboarding, and plugin evidence are generated:

```bash
make open-source-readiness-gate
```

For customer or production-environment certification, aggregate harder
environment-specific evidence into one gate:

```bash
make customer-env-certification-gate \
  RBAC_AUDIT=build/rbac/rbac-audit.json \
  POLICY_APPROVAL_GATE=build/policy-approval/policy-approval-gate.json \
  AUDIT_EXPORT=build/audit/audit-export.csv \
  ROLE_REVIEW=docs/project/role-review.md \
  SIEM_VERIFY=build/siem/siem-verification.json \
  SIEM_CERTIFICATION=build/siem/customer-siem-certification.json \
  UPGRADE_ROLLOUT=build/upgrade/rollout-plan.json \
  SOAK_READINESS=build/performance/soak-readiness.json \
  PRODUCTION_READINESS_GATE=build/production-readiness/production-readiness-gate.json \
  DEPLOYMENT_DIAGNOSTICS_GATE=build/deploy/deployment-diagnostics-gate.json \
  BACKUP_READINESS_GATE=build/backup/backup-readiness-gate.json \
  PLUGIN_CATALOG_GATE=build/plugins/plugin-catalog-gate.json \
  ONBOARDING_MANIFEST=build/onboarding/onboarding-manifest.json \
  REQUIRE_DELEGATED_ADMIN=1 \
  REQUIRE_AUDIT_EXPORT=1 \
  REQUIRE_ROLE_REVIEW=1 \
  REQUIRE_SIEM_CERTIFICATION=1 \
  REQUIRE_TLS=1 \
  REQUIRE_STATE_BACKEND=1 \
  REQUIRED_ONBOARDING_CHECKS="tailscale ssh api tls"
```

This gate blocks missing or stale proof for delegated admin/custom roles,
cross-tenant scoping, audit export, SIEM/SOAR retry/backpressure/field mapping,
fleet canary/pause/resume/rollback planning, 24-hour soak budgets, TLS/state
backend/backup evidence, plugin signing and permission models, and onboarding
environment checks.

Audit export evidence may be CSV or JSON. CSV exports must include at least one
data row after the header; JSON exports may use a top-level list or `events` /
`records` array. Role review evidence may be Markdown or JSON, but it must show
approved role entries with named owners and must not contain pending, TBD,
placeholder, delegate, or unsigned review markers. Use
`MIN_AUDIT_EXPORT_ROWS=N` to require a larger audit sample.

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
  MAX_BATCH_SIZE=25 \
  BATCH_BY_GROUP=1
```

Use `BATCH_BY_GROUP=1` when the fleet inventory includes `group` or
`agent_group` fields. The generated evidence records the agent groups covered
by each canary, wave, and rollback batch, which lets customer certification
validate group-aware rollout coverage instead of only counting agents.

Generate a first-run onboarding bundle for a new customer or lab deployment:

```bash
make onboarding-wizard \
  OUT_DIR=build/onboarding \
  POSTGRES_DSN='postgres://providapt:<password>@postgres:5432/providapt?sslmode=require'
```

The onboarding bundle includes a production-oriented starter config, checklist,
environment checks for Tailscale/SSH/API/TLS/secrets/PostgreSQL, and manifest
that can be attached to customer handoff evidence. It also writes
`onboarding-check-results.template.json`, a fill-in template containing every
generated check command.

After running the environment checks, merge observed results into the
onboarding report:

```json
{
  "checks": [
    {"name": "tailscale", "status": "pass", "observed": "all VM peers online"},
    {"name": "api", "status": "fail", "observed": "connection refused"}
  ]
}
```

```bash
make onboarding-wizard \
  OUT_DIR=build/onboarding \
  CHECK_RESULTS=build/onboarding/check-results.json
```

The generated `onboarding-report.md` summarizes pass/warn/fail/unknown counts,
adds an action summary grouped by check status and severity, and records
prioritized next actions for each failed or unverified check. The same
`action_summary` is written to `onboarding-manifest.json` for release evidence
aggregation.

## 9. Commercialization Readiness

Validate plugin release evidence before enabling customer-specific detection,
scoring, threat-intelligence, or enrichment extensions:

```bash
make plugin-release-gate \
  PLUGIN_MANIFEST=plugins/example/plugin.json \
  PLUGIN_SIGNATURE=plugins/example/plugin.json.sig
```

Close open-source readiness with the open-source readiness gate:

```bash
make open-source-readiness-gate \
  RELEASE_GATES_JSON=build/release-gate-status.json \
  OPERATIONS_READINESS_GATE=build/operations-readiness/operations-readiness-gate.json \
  ENTERPRISE_READINESS=build/enterprise-readiness.json \
  MODEL_LIFECYCLE_GATE=build/evaluation/model-lifecycle-gate.json \
  VISUAL_REGRESSION_SNAPSHOTS=build/visual-regression/visual-regression-snapshots.json \
  ONBOARDING_MANIFEST=build/onboarding/onboarding-manifest.json \
  PLUGIN_GATE=build/plugins/plugin-release-gate.json \
  EXTERNAL_APPROVAL=docs/project/external-approval-request-v1.2.3-rc.1.md
```

The open-source readiness gate verifies release gate status, operations and
enterprise readiness, model promotion packet evidence, visual browser baseline
coverage, onboarding artifacts, open-source documentation, external approval
evidence, and optional plugin release gates. Missing optional local evidence is
a warning for planning runs; supplied evidence that is failed or incomplete
blocks release.

Convert the open-source readiness result into owner-facing action items:

```bash
make open-source-readiness-backlog \
  OPEN_SOURCE_READINESS_GATE=build/open-source-readiness/open-source-readiness-gate.json
```

The generated backlog includes a section checklist, status counts, and
release-blocking section totals in addition to the owner-facing task list.

Aggregate the local open-source milestone package after the readiness and
backlog reports are generated:

```bash
make open-source-development-backlog \
  LOCAL_ONLY=1 \
  RELEASE_EVIDENCE_CONSISTENCY_GATE=build/release-evidence/release-evidence-consistency-gate.json \
  ARTIFACT_SIGNING_GATE=build/release-evidence/artifact-signing-gate.json \
  VISUAL_REGRESSION_GATE=build/visual-regression/visual-regression-gate.json \
  CAPTURE_ENRICHMENT_GATE=build/capture-quality/capture-enrichment-field-gate.json \
  MODEL_LIFECYCLE_GATE=build/evaluation/model-lifecycle-gate.json \
  SOAK_READINESS=build/performance/soak-readiness.json \
  ONBOARDING_MANIFEST=build/onboarding/onboarding-manifest.json
make open-source-milestone ALLOW_MISSING=1
make open-source-evidence-summary ALLOW_MISSING=1
make open-source-local-closure
```

When gate paths are supplied, the development backlog runs in evidence-aware
mode and marks mapped tasks as `done`, `needs_review`, or `needs_fix` based on
the supplied gate status. Multi-evidence tasks, such as final artifacts or
RBAC/customer certification, remain `needs_review` until every mapped evidence
input is present and passing.
The generated backlog also includes a `planning_summary` section with the next
local tasks to work, external blockers, and missing or blocked evidence grouped
by evidence key. Next local tasks are sorted by actionable risk first:
`needs_fix`/blocked evidence, then review/warn or partial evidence, then missing
evidence, while tasks with passing evidence drop out of the next-local list.
The Markdown report includes a ranked task table with the evidence reason and
command to run.

The milestone package includes readiness, readiness backlog, development
backlog, release gate status, release evidence consistency, model lifecycle, and
visual baseline evidence. It also consumes Trace SVG stress evidence from
`TRACE_SVG_STRESS` or `build/trace-stress/trace-svg-stress.json` and onboarding
evidence from `ONBOARDING_MANIFEST` or `build/onboarding/onboarding-manifest.json`
when present.
Model lifecycle evidence includes the promotion readiness summary,
feedback-label distribution, blockers, warnings, and missing approval/drift
inputs when present. Visual baseline evidence includes coverage, viewport
classes, baseline comparison counts, and DOM assertion failure counts when
present. Trace SVG stress evidence includes alert/layout coverage, result and
failure counts, maximum latency, node-count range, and failed layouts.
Onboarding evidence includes check status counts, next-action counts, blocked
checks, warning checks, unknown checks, and top operator actions.
Evidence-aware development backlog inputs are summarized into a
remaining-task section grouped by `needs_fix`, `needs_review`, `needs_evidence`,
`blocked_external`, and missing evidence. The same milestone section carries the
backlog `planning_summary`, including next local tasks, external blockers, and
remaining evidence grouped by key. `ALLOW_MISSING=1` is useful during local
development because it records absent external evidence as warnings instead of
blocking the milestone package. Omit it for final release closure.
`make open-source-evidence-summary` creates a shorter executive summary from
the milestone, readiness backlog, visual gate, Trace SVG stress, and onboarding
manifest, plus model lifecycle promotion evidence when
`MODEL_LIFECYCLE_GATE` or `build/evaluation/model-lifecycle-gate.json` is
present. It is the fastest local view of release blockers before opening the
larger evidence JSON files.
`make open-source-local-closure` creates an honest local closure matrix for the
remaining open-source release tasks: security scans, final artifacts, browser
baselines, Trace SVG stress, model lifecycle, RBAC/audit hardening, plugin
distribution, and first-run onboarding. It records missing scanner/SBOM tools
and missing real-environment inputs separately so release owners can see what
is ready to run locally and what still needs final-tag, server, alert, model,
RBAC, or plugin evidence.
