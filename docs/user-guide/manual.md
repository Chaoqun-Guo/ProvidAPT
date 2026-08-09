# ProvidAPT User Manual

**Release Line:** `v1.2.3-rc.1`

This manual covers day-to-day operation of ProvidAPT, including command-line workflows, provenance investigation, policy operations, reporting, and cleanup guidance.

## 1. Command-Line Tools

ProvidAPT ships with the following primary tools:

- `providaptctl` - control and status operations
- `providaptd` - main daemon
- `providapt-watchdog` - watchdog companion
- `providapt-verify` - integrity verification
- `providapt-deanon` - authorized de-anonymization
- `providapt-heal` - incident response helper

### `providaptctl`

```bash
providaptctl -status
providaptctl -restart
providaptctl -diagnose
providaptctl -verify -json
providaptctl -audit -audit-cat=admin -json
```

### `providaptd`

```bash
sudo providaptd
sudo providaptd -config /etc/providapt/providapt.toml
sudo providaptd -v
```

Loader behavior:

- Prefers `BPF LSM` hooks when supported
- Falls back to `kprobe` mode when LSM attachment is unavailable
- Searches for `lsm_hooks.bpf.o` in:
  - `build/ebpf/lsm_hooks.bpf.o`
  - `/usr/local/lib/providapt/ebpf/lsm_hooks.bpf.o`

Override the object path when needed:

```bash
export PROVIDAPT_BPF_OBJECT_PATH=/opt/providapt/ebpf/lsm_hooks.bpf.o
sudo -E providaptd -config /etc/providapt/providapt.toml
```

### Monitoring Only Specific Commands

Use `capture.include_comms` when a client should focus on specific process
names instead of monitoring every running process:

```yaml
capture:
  include_comms:
    - curl
    - wget
    - ssh
```

Native TOML syntax is also accepted when using a TOML-style configuration:

```toml
[capture]
include_comms = ["curl", "bash"]
```

Command values are normalized to Linux task `comm` names. You can use either
the basename (`curl`) or an executable path (`/usr/bin/curl`); matching is
case-insensitive and uses the kernel `comm` length limit.

The same setting can be supplied through the environment:

```bash
export PROVIDAPT_CAPTURE_INCLUDE_COMMS=curl,wget,ssh
sudo -E providaptd -config /etc/providapt/providapt.yaml
```

`include_comms` is enforced before events enter the provenance graph, storage,
and alert pipeline. At startup, ProvidAPT also excludes currently running
non-matching processes in the kernel PID exclusion map. Combine this allow-list
with rules and hot paths when you need higher-fidelity detection for those
commands.

### `providapt-watchdog`

```bash
sudo providapt-watchdog
```

### `providapt-verify`

```bash
sudo providapt-verify -data /var/lib/providapt/store
sudo providapt-verify -data /var/lib/providapt/store -verbose
sudo providapt-verify -data /var/lib/providapt/store -output /tmp/integrity_report.txt
```

Exit codes:

- `0`  ->  all checks passed
- `2`  ->  tampering detected

### `providapt-deanon`

```bash
providapt-deanon -hash a3f8b2c1e4d5f6a7 -key /etc/providapt/deanon.key
providapt-deanon -list -key /etc/providapt/deanon.key
```

### `providapt-heal`

```bash
providapt-heal -pid 1234
providapt-heal -pid 1234 -rollback -dry-run=false
providapt-heal -pid 1234 -firewall
providapt-heal -pid 1234 -output /tmp/impact_report.json
```

## 2. ProvQL Investigation Examples

### Sensitive File Access

```sql
MATCH (p:Process)-[:READ]->(f:File)
WHERE f.path = '/etc/shadow'
RETURN p.pid, p.comm, f.path
```

### SSH Lateral Movement

```sql
MATCH (p:Process)-[:CONNECTED]->(n:Network)
WHERE n.label CONTAINS ':22' AND p.comm = 'ssh'
RETURN p.pid, p.comm, n.label
```

### `curl -> temp file -> shell`

```sql
MATCH (a:Process)-[:WROTE]->(f:File)-[:READ]->(b:Process)
WHERE f.path STARTSWITH '/tmp'
  AND a.comm CONTAINS 'curl'
  AND b.comm = 'bash'
RETURN a.comm, f.path, b.comm
```

## 3. Operational APIs

Frequently used control-plane endpoints:

- `GET /api/v1/status`
- `GET /api/v1/graph/export`
- `GET /api/v1/investigation/report?pid=<pid>`
- `GET /api/v1/alerts`
- `POST /api/v1/control/support`
- `GET /api/v1/control/support/download`
- `GET /api/v1/control/backup`
- `POST /api/v1/control/backup`
- `GET /api/v1/control/backup/download`
- `GET /api/v1/control/compliance`
- `POST /api/v1/control/compliance`
- `GET /api/v1/control/security`
- `POST /api/v1/control/security`
- `GET /api/v1/control/upgrade`
- `POST /api/v1/control/upgrade`

## 4. Control Plane Console

The main console is available at:

```text
http://<server>:18080/
```

Use the console as the daily operator entry point:

| Area | Purpose | Typical Action |
| --- | --- | --- |
| Summary bar | Version, fleet size, memory, node, and edge counters | Confirm the system is healthy before investigations |
| Agent Overview | Fleet state, host metadata, kernel, OS, uptime, and report age | Filter stale or offline agents and open host details |
| Policy Center | Draft, validate, diff, publish, and rollback policies | Review policy changes before pushing to agents |
| Delivery Health | SIEM, audit, support bundle, and evidence delivery state | Retry failed delivery or inspect outbox pressure |
| Alert Workflow | Alert triage, assignment, silence, reopen, close, and trace links | Move alerts through investigation and closure |
| Investigation | Provenance graph, SVG trace, Markdown report, and node filters | Focus on process, file, network, and host relationships |

Recommended workflow:

1. Check the summary bar and fleet freshness.
2. Open `Agent Overview` and filter to the target host or group.
3. Open `Alert Workflow` and select the alert or process of interest.
4. Use `Trace SVG`, `Download Markdown`, or graph node filters to inspect provenance.
5. If a rule change is required, use `Policy Center` to edit, validate, diff, and publish.
6. Confirm `Delivery Health` after SIEM, support bundle, or evidence export actions.

## 5. Policy Operations

Policy changes should be reviewed as a draft before publishing:

```bash
curl http://<server>:18080/api/v1/control/policies
curl -X POST http://<server>:18080/api/v1/control/policies \
  -H "Content-Type: application/json" \
  -d '{"action":"validate","draft":"rules:\\n  - id: suspicious-curl\\n    severity: WARNING"}'
```

Operator rules:

- Validate syntax before publishing.
- Review the generated diff before pushing changes to agents.
- Use approvals for `policy.publish` and `policy.rollback` in production.
- Keep rule IDs stable so alert history remains searchable across versions.

## 6. Alert Workflow

The alert workflow supports bulk and single-alert actions:

```bash
curl -X POST http://<server>:18080/api/v1/control/alerts \
  -H "Content-Type: application/json" \
  -d '{"action":"assign","alert_ids":["alert-a"],"assignee":"secops@example.com","note":"initial triage"}'
```

Supported workflow actions include:

- assign
- silence / unsilence
- reopen
- close
- add triage note
- open provenance trace
- download investigation report

Use silence for maintenance windows, close only after the investigation record is complete, and prefer reopen when new evidence invalidates a closure.

## 7. Reporting and Evidence

Useful outputs:

- Support bundles for support and incident handoff
- MITRE heatmap reports
- Audit feed exports for administrative actions
- Graph exports for post-incident analysis
- Investigation reports in JSON or Markdown:

```bash
curl "http://<server>:18080/api/v1/investigation/report?pid=1234&direction=backward&depth=5"
curl "http://<server>:18080/api/v1/investigation/report?node=p:1234&format=markdown"
```

Policy and alert workflow evidence:

- `GET /api/v1/control/policies` includes a `diff` section comparing the current
  published policy with the draft.
- `POST /api/v1/control/alerts` accepts `alert_ids` for bulk close, silence,
  unsilence, reopen, or assignment actions.
- Alert workflow items include SLA deadline/status fields when generated by the
  daemon control plane.

## 8. Performance Tuning

Recommended defaults:

- Use SSD-backed storage for the Pebble data directory
- Keep archive redaction enabled in production
- Monitor ring-buffer pressure and dropped-event counters
- Prefer `make build-core` and `go test ./...` as standard release checks

## 9. Uninstall and Cleanup

```bash
providaptctl -stop
sudo systemctl disable providapt
sudo rm -rf /var/lib/providapt/store
sudo rm -rf /var/log/providapt
sudo rm -f /etc/providapt/providapt.toml
```
