# Agent and Server Topology

This example shows the intended commercial topology: one control-plane server monitors and configures multiple Linux agents.

## Roles

| Role | Responsibility |
| --- | --- |
| Server | Dashboard, fleet overview, policy distribution, alert workflow, SIEM delivery, PostgreSQL storage |
| Agent | eBPF capture, local filtering, health reports, provenance event forwarding |

## Server Checklist

```bash
sudo cp examples/config/providapt.production.yaml /etc/providapt/providapt.yaml
providaptctl -config-check -config /etc/providapt/providapt.yaml
sudo systemctl enable --now providapt.service
curl -s http://localhost:18080/api/v1/control/fleet
```

## Agent Checklist

```bash
sudo cp examples/config/providapt.local.toml /etc/providapt/providapt.toml
sudo systemctl enable --now providapt.service
providaptctl -status
```

Configure each agent with:

- stable `agent_id`
- server gRPC endpoint
- TLS trust roots or API token
- optional `capture.include_comms` allow-list
- host tags such as environment, owner, and workload

## Small Disk / High Event Rate Hosts

Use explicit log budgets and command allow-lists on noisy virtual machines:

```yaml
output:
  max_file_bytes: 16777216
  retain_files: 1
  alert_max_file_bytes: 8388608
  alert_retain_files: 1
capture:
  auto_exclude_noisy: true
  include_comms: ["curl", "bash", "sh", "ssh", "scp", "python", "python3"]
```

The dashboard event cards open structured details for `process`, typed `payload`,
`enrich`, and raw compatibility fields. Alert Workflow also provides `Open
Events` to search related event records without leaving the console.

## Repeatable VM Deployment

After building `build/bin/providaptd`, deploy without leaving large archives on
the VMs:

```bash
PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-slave.<TAILSCALE_DOMAIN> centos@vm-centos-slave.<TAILSCALE_DOMAIN> ubuntu@vm-ubuntu-master.<TAILSCALE_DOMAIN>" \
  bash scripts/deploy/deploy-vms.sh
```

The script uploads only the daemon binary, restarts the service, and removes old
`providapt-*.ndjson` and `alerts*.ndjson` files.

## Validation

On the server:

```bash
curl -s http://localhost:18080/api/v1/control/fleet
curl -s http://localhost:18080/api/v1/control/overview
```

On each agent:

```bash
sudo journalctl -u providapt.service -n 100 --no-pager
cat /sys/kernel/security/lsm
```
