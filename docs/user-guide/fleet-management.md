# Fleet Management

The control plane monitors reporting agents, stores fleet metadata, and coordinates policy rollout state.

## Agent States

| State | Meaning |
| --- | --- |
| `HEALTHY` | recent healthy summary received |
| `DEGRADED` | agent reported an unhealthy pipeline, store, or dependency |
| `STALE` | report age exceeded stale threshold |
| `OFFLINE` | report age exceeded offline threshold |

## Enrollment States

| Enrollment | Behavior |
| --- | --- |
| `approved` | normal telemetry and policy instructions |
| `quarantined` | telemetry allowed, policy advancement withheld |
| `revoked` | telemetry acknowledgement rejected and policy target excluded |

## View Fleet

```bash
curl -s http://<server>:18080/api/v1/control/fleet
curl -s "http://<server>:18080/api/v1/control/fleet?group=prod&tag=linux"
```

Wrapper:

```bash
export PROVIDAPT_SERVER_URL=http://<server>:18080
make ops-fleet-list
bash scripts/ops/fleet-lifecycle.sh --server "$PROVIDAPT_SERVER_URL" list --group prod --tag linux
```

## Update Enrollment

```bash
curl -X POST http://<server>:18080/api/v1/control/fleet \
  -H "Content-Type: application/json" \
  -d '{"agent_ids":["agent-a"],"action":"quarantined","note":"incident containment"}'
```

Wrapper:

```bash
bash scripts/ops/fleet-lifecycle.sh --server "$PROVIDAPT_SERVER_URL" \
  action --agent agent-a --state quarantined --note "incident containment"
make ops-fleet-action \
  FLEET_AGENTS=agent-a \
  FLEET_STATE=approved \
  FLEET_NOTE="host identity reviewed"
```

Use `approved` after enrollment review, `quarantined` during active
investigation, and `revoked` when an agent identity is retired or distrusted.
The wrapper and Make target can write JSON and Markdown evidence with
per-agent success or failure details under `build/fleet/`.

## Lifecycle Plans

Generate an auditable dry-run plan before certificate rotation, quarantine, or
decommissioning:

```bash
export PROVIDAPT_SERVER_URL=http://<server>:18080
make ops-fleet-plan FLEET_OPERATION=cert-rotation FLEET_GROUP=prod FLEET_TAG=linux
bash scripts/ops/fleet-lifecycle.sh --server "$PROVIDAPT_SERVER_URL" \
  plan --operation decommission --agent agent-a,agent-b \
  --out-json build/fleet/decommission.json \
  --out-md build/fleet/decommission.md
```

Plans include target agents, current enrollment state, health, certificate
fingerprint, and runbook steps. They do not mutate the fleet; use `action` only
after the plan is reviewed and approved.

## Metadata

Use group and tags to model ownership and rollout scope:

- `group`: tenant, environment, or business unit
- `tags`: workload, region, kernel family, sensitivity, or maintenance window
- `note`: human-readable operator context

## Operating Practices

- approve new agents only after host identity is understood
- quarantine compromised or under-investigation hosts
- revoke decommissioned or stolen agent identities
- use group/tag targeting for policy rollout
- monitor `last_report_age_seconds` before investigating missing telemetry
