# Dashboard API Guide

The dashboard is backed by REST endpoints under `/api/v1/`.

## Main Panels

| Dashboard Area | Primary Endpoint | Purpose |
| --- | --- | --- |
| Summary bar | `/api/v1/status`, `/api/v1/control/overview` | health, version, counters, activation |
| Agent Overview | `/api/v1/control/fleet` | agent state, metadata, enrollment |
| Policy Center | `/api/v1/control/policies` | draft, diff, validate, publish, rollback |
| Delivery Health | `/api/v1/control/compliance` | SIEM, retention, reports, approvals |
| Alert Workflow | `/api/v1/alerts`, `/api/v1/control/alerts` | triage, assignment, silence, close, reopen |
| Investigation | `/api/v1/investigation/report`, `/api/v1/graph/export` | trace, SVG/Markdown export, graph filters |
| License / Upgrade | `/api/v1/control/license`, `/api/v1/control/upgrade` | activation, renewal, preflight, apply, rollback |

## Mutation Pattern

Mutation endpoints generally accept JSON with:

```json
{
  "action": "example.action",
  "note": "operator context"
}
```

High-risk actions should be protected by RBAC and compliance approvals.

## UI Expectations

- Buttons should map to a concrete API action or navigation target.
- Counters should act as filters when a corresponding list exists.
- Empty states should explain whether no data exists or the configured data path is missing.
- Failed requests should display the server error and suggested operator action.
