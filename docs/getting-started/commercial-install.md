# Commercial Linux Installation

This guide describes the customer-facing Linux installation path for ProvidAPT agents and control-plane hosts.

## Installed Layout

| Path | Purpose |
| --- | --- |
| `/usr/local/sbin/providaptd` | Main daemon |
| `/usr/local/sbin/providapt-watchdog` | Optional watchdog binary |
| `/usr/local/bin/providaptctl` | CLI control utility |
| `/usr/local/lib/providapt/ebpf` | eBPF object files |
| `/etc/providapt/providapt.toml` | Main configuration |
| `/etc/default/providapt` | systemd environment overrides |
| `/etc/systemd/system/providapt.service` | systemd service unit |
| `/var/lib/providapt` | Stateful runtime data |
| `/var/log/providapt` | Logs and operational output |
| `/var/log/providapt/control-plane-state.json` | Control-plane fleet metadata and policy history when running as a server |
| `/var/log/providapt/policy-bundles/policy-v*.json` | Versioned policy bundle snapshots |
| `/var/log/providapt/applied-policy-state.json` | Agent-side last applied policy version and acknowledgement record |

## Install From Local Build

```bash
make build-core
sudo scripts/install/install-linux.sh
sudo systemctl status providapt.service
```

Set `START_SERVICE=0` to install without starting:

```bash
sudo START_SERVICE=0 scripts/install/install-linux.sh
```

## Install From Tarball

```bash
tar xzf providapt-<version>-linux-<arch>.tar.gz
cd providapt-<version>-linux-<arch>
sudo ./install.sh
```

## Service Configuration

Edit `/etc/default/providapt` for operational overrides:

```bash
PROVIDAPT_DAEMON_ARGS="-log-level=info"
PROVIDAPT_BPF_OBJECT_PATH="/usr/local/lib/providapt/ebpf/lsm_hooks.bpf.o"
```

Then restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart providapt.service
```

## Upgrade Preflight

Run preflight before replacing packages or binaries:

```bash
sudo scripts/upgrade/preflight-linux.sh
sudo EXPECTED_SHA256=<sha256> scripts/upgrade/preflight-linux.sh /path/to/package.tar.gz
```

The preflight checks systemd registration, config readability, kernel version, BTF or kprobe fallback availability, disk capacity, and optional package checksum.

## Uninstall

Keep configuration and data:

```bash
sudo scripts/install/uninstall-linux.sh
```

Purge configuration and data:

```bash
sudo PURGE_DATA=1 scripts/install/uninstall-linux.sh
```

## Commercial Release Gate

Before shipping to customers:

1. Build `.deb`, `.rpm`, and `.tar.gz` from the same Git tag.
2. Generate and sign `checksums.txt`.
3. Attach SBOM and release readiness report.
4. Validate a fresh install, restart, upgrade preflight, and uninstall on each supported distribution.
5. Record known kernel or BPF limitations in the release notes.

## Current Control-Plane Policy Deployment Status

The control plane records policy publish and rollback deployment plans with:

- deployment status
- target agent count
- acknowledged agent count
- agents awaiting approval count

`queued` means the control plane has created the deployment plan for currently reporting agents. `applied` means all currently targeted agents have reported the desired policy version through telemetry.

Fleet group/tag metadata and policy publish history are persisted to `control-plane-state.json`, so a control-plane restart preserves operator organization and policy release history.

Telemetry acknowledgements include the current control-plane policy version (`policy_version=<n>`). Agents record the last acknowledgement and desired policy version in their health status, then include `applied_policy_version` in subsequent telemetry summaries.

Each publish or rollback writes a versioned policy bundle under `policy-bundles/` and records its SHA-256 hash in Policy Center. The bundle is the reviewable operational artifact for the policy version and includes Sigma rules, whitelist entries, and taint sources known to the control plane at publish time.

Operators can download the current or historical bundle from Policy Center, or directly through `/api/v1/control/policies/bundle?version=<n>`.

## Control-Plane HA and Automatic Failover

ProvidAPT exposes control-plane HA readiness through `/api/v1/control/ha`.
In production `active-passive` mode, control-plane nodes write heartbeats into
PostgreSQL and automatically elect the active leader. If the current leader
misses the election timeout, the remaining healthy node with the lowest stable
node ID is promoted. PostgreSQL updates run in a transaction protected by an
advisory lock, so concurrent heartbeats cannot split-brain the leader record.

```yaml
control_plane:
  mode: active-passive
  node_id: cp-1
  role: follower
  leader_id: cp-0  # optional preferred leader while healthy
  peers:
    - cp-0=https://cp-0.example.com:18080
    - cp-1=https://cp-1.example.com:18080
  state_backend: postgresql://providapt:${PROVIDAPT_PG_PASSWORD}@postgres.example.com:5432/providapt?sslmode=require
  heartbeat: 10s
  election_timeout: 45s
  failover_ready: true
```

Supported modes are `standalone`, `active-passive`, and `external`. Supported
roles are `leader`, `follower`, and `observer`. For automatic failover, set
`state_backend` to a PostgreSQL or PostgreSQL-compatible DSN beginning with
`postgres://` or `postgresql://`. ProvidAPT creates and maintains the
`providapt_control_plane_ha` table automatically. `failover_ready` is reported
as true when HA mode is enabled, PostgreSQL is writable, and at least two
healthy control-plane nodes are active. File-backed state is retained only for
local testing; production deployments should use PostgreSQL. Use `external`
mode when Kubernetes, a load balancer, or another orchestrator owns leader
election.

For Docker-based production deployments, enable the bundled PostgreSQL container
through Ansible:

```bash
PROVIDAPT_POSTGRES_ENABLED=true \
PROVIDAPT_POSTGRES_PASSWORD='<strong-password>' \
PROVIDAPT_CONTROL_PLANE_MODE=active-passive \
ansible-playbook -i inventory.yml deploy/ansible/playbook.yml --tags postgres,providapt
```

The playbook runs `postgres:16-alpine` as `providapt-postgres`, stores data under
`/var/lib/providapt/postgres`, maps port `5432` by default, and passes the
generated PostgreSQL DSN to ProvidAPT as `PROVIDAPT_CONTROL_PLANE_STATE_BACKEND`.
Override `PROVIDAPT_POSTGRES_HOST`, `PROVIDAPT_POSTGRES_PORT`,
`PROVIDAPT_POSTGRES_DB`, `PROVIDAPT_POSTGRES_USER`, and
`PROVIDAPT_POSTGRES_SSLMODE` when deploying a dedicated database host or a
managed PostgreSQL service.

Follower nodes continue serving read-only control-plane views, including health,
fleet overview, HA status, audit feed, and policy bundle downloads. Mutating
operations such as fleet enrollment changes, policy publish or rollback, upgrade
actions, backup actions, support bundle generation, delivery replay, alert
workflow updates, and admin reload are accepted only by the current healthy
leader. A follower returns HTTP `409 Conflict` with the current `leader_id` and
`leader_endpoint` so automation and the dashboard can retry against the active
node automatically.

Agents can automatically pull and apply the desired policy version after telemetry acknowledgement. Configure:

```yaml
policy:
  endpoint: "http://CONTROL_PLANE_HOST:18080"
  api_key: "admin-or-auditor-api-key"
  bundle_dir: "/var/log/providapt/applied-policy-bundles"
```

If `policy.endpoint` is omitted, the agent attempts to derive `http://<telemetry-host>:18080` from `telemetry.endpoint`. Set `PROVIDAPT_POLICY_ENDPOINT` explicitly in production when the REST control-plane port differs.

## Agent Enrollment Operations

Fleet operators can mark each reporting agent as:

- `approved` for normal operation
- `quarantined` for restricted investigation
- `revoked` for denied or compromised hosts

Enrollment status is stored with fleet metadata in `control-plane-state.json`, shown in Agent Overview, and recorded in the admin audit log when changed from the dashboard or API.

`revoked` agents are rejected at telemetry acknowledgement time and do not count toward policy rollout targets. When mTLS is enabled, the control plane also remembers the reported client certificate SHA-256 fingerprint and rejects future handshakes for certificates tied to revoked enrollment records. `quarantined` agents may still report telemetry, but the control plane withholds policy version instructions so they cannot silently advance to new policy bundles during investigation.

Admins can edit the policy draft from Policy Center before publishing:

- `add_sigma`, `update_sigma`, `remove_sigma` with `rule_id` and optional `rule_yaml`
- `add_whitelist`, `remove_whitelist`, `clear_whitelist` with whitelist target/value fields
- `add_taint`, `remove_taint` with taint prefix and optional label

Policy publish and rollback actions can target all agents, a specific fleet group, a specific tag, or a group/tag intersection. Revoked agents are excluded from rollout target counts.

Policy edits, publishes, rollbacks, and fleet metadata updates are written to the persisted admin audit log.

Audit records can be exported as CSV for compliance review:

```text
/api/v1/control/audit?category=admin&format=csv
```

Checkpoint backups can be created and downloaded from the dashboard or API:

```text
POST /api/v1/control/backup {"action":"create"}
GET /api/v1/control/backup/download
```

Restore actions are intentionally staged instead of replacing the live store. Use `{"action":"restore_staging"}` to extract the latest backup into `restore-staging/`, verify the restored Pebble store offline, then stop ProvidAPT before swapping directories during a maintenance window.

For production, enable automatic checkpoint backups:

```yaml
backup:
  enabled: true
  interval: 24h
  retain_archives: 7
  min_free_bytes: 1073741824
```

Use `{"action":"prepare_cutover"}` after a successful staging restore to generate a root-only activation script under `restore-staging/`. The script stops `providapt.service`, archives the previous store directory, swaps in the staged restore, and starts the service again.

Security rotation is available from:

```text
GET /api/v1/control/security
POST /api/v1/control/security {"action":"rotate_server_cert"}
```

The rotation action backs up the previous server cert/key with timestamp suffixes. Reload or restart services after rotation so listeners pick up the new certificate.

For offline bootstrap or staged certificate replacement, generate a reviewed
certificate bundle before rollout:

```bash
make ops-tls-bootstrap \
  TLS_OUT=build/tls \
  TLS_SERVER_CN=cp-0.example.com \
  TLS_SERVER_SAN="DNS:cp-0.example.com,IP:192.168.150.132" \
  TLS_AGENT_CNS="ubuntu-129,centos-131"
```

Copy `ca.crt`, `server.crt`, `server.key`, and each agent certificate/key to the
target hosts, then update the `tls.*`, `telemetry.*`, and `policy.*` paths in
the production configuration.

Offline license activation and renewal use the same endpoint:

```text
POST /api/v1/control/license {"action":"import","license_data":"..."}
POST /api/v1/control/license {"action":"renew","license_data":"..."}
```

License documents may include `machine_fingerprint`; ProvidAPT compares it with the local fingerprint returned by `GET /api/v1/control/license` before accepting the license.

For enterprise SSO, place ProvidAPT behind an authenticated reverse proxy and enable trusted headers only on the protected listener:

```yaml
sso:
  trusted_header_auth: true
  user_header: X-Forwarded-User
  role_header: X-Forwarded-Role
  tenant_header: X-Forwarded-Tenant
```

Tenant-scoped API keys can be bound with `api.auth_tenants`; non-admin users with a tenant are restricted to the matching fleet group.

Policy authors can validate a Sigma rule without mutating the draft:

```text
POST /api/v1/control/policies {"action":"validate_sigma","rule_yaml":"title: ..."}
```

## Compliance Operations

ProvidAPT exposes a compact commercial compliance control plane for audit retention visibility, SIEM handoff tests, change approvals, and release evidence reports:

```yaml
compliance:
  retention_days: 180
  max_audit_entries: 10000
  report_dir: /var/log/providapt/compliance
  report_interval: 24h
  require_approvals: true
  approval_ttl: 24h
  approval_actions:
    - policy.publish
    - policy.rollback
    - upgrade.preflight
    - upgrade.apply
    - upgrade.rollback
    - backup.prepare_cutover

siem:
  enabled: true
  provider: splunk
  endpoint: file:///var/log/providapt/siem.ndjson
  token: env:PROVIDAPT_SIEM_TOKEN
  index: providapt
  source_type: providapt:audit
  format: json
  min_severity: WARNING
  outbox_dir: /var/log/providapt/siem-outbox
  flush_interval: 30s
```

Useful operations:

```text
GET  /api/v1/control/compliance
POST /api/v1/control/compliance {"action":"export_audit","format":"csv"}
POST /api/v1/control/compliance {"action":"apply_retention"}
POST /api/v1/control/compliance {"action":"generate_report"}
POST /api/v1/control/compliance {"action":"generate_report","format":"html"}
POST /api/v1/control/compliance {"action":"test_siem"}
POST /api/v1/control/compliance {"action":"request_approval","target":"policy.publish"}
POST /api/v1/control/compliance {"action":"approve","approval_id":"appr-000001"}
```

The dashboard includes a `Compliance & SIEM` panel with audit export, retention, report generation, and SIEM test controls. Generated evidence files are written under `compliance.report_dir` or `<output.dir>/compliance` by default.

Commercial behavior:

- SIEM events are queued in the outbox and flushed on `siem.flush_interval`.
- `file://`, `http://`, `https://`, `tcp://`, and `udp://` SIEM endpoints are supported; `siem.provider: splunk` sends Splunk HEC events and `siem.provider: elastic` sends Elastic `_bulk` payloads.
- Approval requests are persisted under `<output.dir>/compliance/approvals.json`, expire after `compliance.approval_ttl`, and approved high-risk actions consume one approval.
- Audit retention archives old entries under the compliance report directory and rewrites the active audit log with retained entries.
- HTML compliance reports can be generated on demand and are scheduled by `compliance.report_interval`; reports include readiness score, grade, tenant scope, audit retention, SIEM status, and approval counts.
- License files or `license.max_agents` may enforce reporting-agent seat limits.
- Upgrade `apply` and `rollback` actions use `upgrade.apply_command` and `upgrade.rollback_command` after checksum/signature preflight and required approvals.

Managed multi-tenant behavior:

- Tenant-scoped API keys from `api.auth_tenants` are restricted to their fleet group across Agent Overview, Fleet, Audit Feed, and Compliance status.
- Tenant-filtered audit entries match `tenant`, `group`, `target_group`, or comma-separated `tags` metadata in persisted audit details.

Release packages can be built from the same tagged build output with `nfpm`:

```bash
PROVIDAPT_VERSION=1.2.3 nfpm package -f packaging/nfpm.yaml -p deb
PROVIDAPT_VERSION=1.2.3 nfpm package -f packaging/nfpm.yaml -p rpm
PROVIDAPT_VERSION=1.2.3 nfpm package -f packaging/nfpm.yaml -p tar
```
