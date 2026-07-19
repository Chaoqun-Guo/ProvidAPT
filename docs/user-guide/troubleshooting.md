# Troubleshooting Guide

This guide lists common operational issues and the fastest checks to run before escalating.

## Service Does Not Start

Check systemd and recent logs:

```bash
sudo systemctl status providapt.service --no-pager
sudo journalctl -u providapt.service -n 200 --no-pager
```

Common causes:

- configuration validation failed
- required paths under `/etc/providapt`, `/var/log/providapt`, or `/var/lib/providapt` are missing
- another process already uses port `18080`, `50051`, or the metrics port
- eBPF object file is missing from `/usr/local/lib/providapt/ebpf/`

Validate the configuration:

```bash
providaptctl -config-check -config /etc/providapt/providapt.toml
```

## eBPF or LSM Is Not Active

Check kernel capabilities:

```bash
uname -r
cat /sys/kernel/security/lsm
test -r /sys/kernel/btf/vmlinux && echo "BTF available"
sudo bpftool prog show | grep providapt || true
```

If `bpf` is not listed in `/sys/kernel/security/lsm`, enable it through the kernel command line where supported:

```text
lsm=landlock,lockdown,yama,integrity,apparmor,bpf
```

Reboot after changing the kernel command line.

## Dashboard Shows Empty Graphs

Check whether data exists:

```bash
curl -s http://localhost:18080/api/v1/status
curl -s http://localhost:18080/api/v1/graph/export
ls -la /var/log/providapt /var/lib/providapt
```

Expected fixes:

- create the configured output and storage directories
- confirm the daemon is running as root or has required BPF capabilities
- generate a fresh process, file, or network event after the daemon starts
- confirm `capture.include_comms` is not filtering out the command being tested

## Agent Is Offline in the Control Plane

Check the agent identity and server endpoint:

```bash
providaptctl -status
grep -E "agent|server|grpc|telemetry" /etc/providapt/providapt.toml
```

On the server:

```bash
curl -s http://localhost:18080/api/v1/control/fleet
curl -s http://localhost:18080/api/v1/control/overview
```

Common causes:

- agent cannot reach the server gRPC endpoint
- TLS or API token mismatch
- clock drift makes health reports appear stale
- firewall blocks the telemetry port

## PostgreSQL Connection Fails

Check the configured DSN and container state:

```bash
docker compose ps postgres
docker compose logs --tail=100 postgres
psql "$PROVIDAPT_DATABASE_DSN" -c "select 1"
```

Common fixes:

- confirm the database name, user, password, and network are correct
- wait for PostgreSQL health checks before starting the control plane
- ensure production deployments do not use the local Pebble fallback unless explicitly intended

## SIEM Delivery Is Delayed

Check outbox and delivery status:

```bash
curl -s http://localhost:18080/api/v1/control/compliance
find /var/log/providapt/siem-outbox -type f | head
```

Common causes:

- SIEM token is missing or expired
- endpoint URL is unreachable from the server
- `siem.min_severity` filters out low-severity events
- outbound proxy or firewall blocks HTTP, TCP, or UDP delivery

## Support Bundle for Escalation

Generate a support bundle before changing state:

```bash
curl -X POST http://localhost:18080/api/v1/control/support \
  -H "Content-Type: application/json" \
  -d '{"action":"prepare","note":"pre-escalation bundle"}'
curl -O http://localhost:18080/api/v1/control/support/download
```

Attach:

- support bundle archive
- daemon logs
- configuration with secrets redacted
- kernel version and LSM output
- steps that reproduce the issue
