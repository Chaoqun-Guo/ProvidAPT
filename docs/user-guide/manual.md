# ProvidAPT User Manual

**Release Line:** `v1.2.1`

This manual covers day-to-day operation of ProvidAPT, including command-line workflows, provenance investigation, policy operations, reporting, and cleanup guidance.

## 1. Command-Line Tools

ProvidAPT ships with the following primary tools:

- `providaptctl` ? control and status operations
- `providaptd` ? main daemon
- `providapt-watchdog` ? watchdog companion
- `providapt-verify` ? integrity verification
- `providapt-deanon` ? authorized de-anonymization
- `providapt-heal` ? incident response helper

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

- `0` ? all checks passed
- `2` ? tampering detected

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
- `GET /api/v1/alerts`
- `POST /api/v1/control/support`
- `GET /api/v1/control/support/download`
- `GET /api/v1/control/license`
- `POST /api/v1/control/license`
- `GET /api/v1/control/upgrade`
- `POST /api/v1/control/upgrade`

## 4. Reporting and Evidence

Useful outputs:

- Support bundles for support and incident handoff
- MITRE heatmap reports
- Audit feed exports for administrative actions
- Graph exports for post-incident analysis

## 5. Performance Tuning

Recommended defaults:

- Use SSD-backed storage for the Pebble data directory
- Keep archive redaction enabled in production
- Monitor ring-buffer pressure and dropped-event counters
- Prefer `make build-core` and `go test ./...` as standard release checks

## 6. Uninstall and Cleanup

```bash
providaptctl -stop
sudo systemctl disable providapt
sudo rm -rf /var/lib/providapt/store
sudo rm -rf /var/log/providapt
sudo rm -f /etc/providapt/providapt.toml
```
