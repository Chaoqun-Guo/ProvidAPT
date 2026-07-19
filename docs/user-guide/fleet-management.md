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

## Update Enrollment

```bash
curl -X POST http://<server>:18080/api/v1/control/fleet \
  -H "Content-Type: application/json" \
  -d '{"agent_ids":["agent-a"],"action":"quarantined","note":"incident containment"}'
```

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
