# Dashboard API Guide

The dashboard is backed by REST endpoints under `/api/v1/`.

The UI shell is embedded from `pkg/api/templates/dashboard_shell.html`, metrics
from `pkg/api/templates/dashboard_metrics.html`, panel ordering from
`pkg/api/templates/dashboard_panels.html`, and individual panels from
`pkg/api/templates/panels/`. Primary styles, responsive viewport rules, and
JavaScript are embedded separately from `pkg/api/static/dashboard.css`,
`pkg/api/static/dashboard-responsive.css`, `pkg/api/static/dashboard-api.js`,
`pkg/api/static/dashboard-state.js`, `pkg/api/static/dashboard-ui.js`,
`pkg/api/static/dashboard-layout.js`, and `pkg/api/static/dashboard.js`.

The Trace Viewer shell is rendered by `pkg/api/svg.go`; its styles and
JavaScript are embedded separately from `pkg/api/static/trace-viewer.css` and
`pkg/api/static/trace-viewer.js`.

## Main Panels

| Dashboard Area | Primary Endpoint | Purpose |
| --- | --- | --- |
| Summary bar | `/api/v1/status`, `/api/v1/control/overview` | health, version, and runtime counters |
| Agent Overview | `/api/v1/control/fleet` | agent state, metadata, enrollment |
| Policy Center | `/api/v1/control/policies` | draft, diff, validate, publish, rollback |
| Delivery Health | `/api/v1/control/compliance` | SIEM, retention, reports, approvals |
| Alert Workflow | `/api/v1/alerts`, `/api/v1/control/alerts`, `/api/v1/control/alerts/feedback` | triage, assignment, silence, close, reopen, analyst feedback export |
| Investigation | `/api/v1/investigation/report`, `/api/v1/graph/export` | trace, SVG/Markdown export, graph filters |
| Upgrade | `/api/v1/control/upgrade` | manifest discovery, preflight, apply, rollback |

## Mutation Pattern

Mutation endpoints generally accept JSON with:

```json
{
  "action": "example.action",
  "note": "operator context"
}
```

High-risk actions should be protected by RBAC and compliance approvals.

## Alert Feedback Ledger

`POST /api/v1/control/alerts` accepts `annotate`, `assign`, `close`, `reopen`,
`silence`, and `unsilence`. If no live workflow manager is attached, the control
plane stores these analyst actions in an append-only `alert-feedback.ndjson`
ledger and merges the latest entry into subsequent `GET /api/v1/control/alerts`
responses.

`GET /api/v1/control/alerts/feedback` returns JSON feedback evidence. Add
`?format=csv` to export `providapt-alert-feedback.csv` for release evidence,
detector training review, and operator SOC handoff.

## UI Expectations

- Buttons should map to a concrete API action or navigation target.
- Counters should act as filters when a corresponding list exists.
- Empty states should explain whether no data exists or the configured data path is missing.
- Failed requests should display the server error and suggested operator action.

## Visual Regression

`make visual-regression-snapshots` captures Dashboard and Trace Viewer
screenshots at `390x844`, `1366x768`, `1920x1080`, and `2560x1080`.
Dashboard captures include DOM overflow checks. Trace Viewer captures verify
that browser-rendered SVG, layout controls, PNG/SVG/raw export controls, and
report links are usable before `make visual-regression-gate` accepts the
manifest. Passing captures can be promoted with
`PROMOTE_BASELINE=build/visual-regression/baseline`; the promotion step copies
PNG files into that baseline directory and rewrites the baseline manifest to use
the promoted paths.
