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
