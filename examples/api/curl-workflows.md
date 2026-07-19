# API curl Workflows

These examples use the HTTP API exposed by the control plane on port `18080`.

Set common variables:

```bash
export PROVIDAPT_URL=http://localhost:18080
export PROVIDAPT_TOKEN=replace-with-api-token
alias providapt_api='curl -fsS -H "Authorization: Bearer $PROVIDAPT_TOKEN"'
```

## Status and Overview

```bash
providapt_api "$PROVIDAPT_URL/api/v1/status"
providapt_api "$PROVIDAPT_URL/api/v1/control/overview"
providapt_api "$PROVIDAPT_URL/api/v1/control/fleet"
```

## Alerts

```bash
providapt_api "$PROVIDAPT_URL/api/v1/alerts"
providapt_api -X POST "$PROVIDAPT_URL/api/v1/control/alerts" \
  -H "Content-Type: application/json" \
  -d '{"action":"assign","alert_ids":["alert-a"],"assignee":"secops@example.com","note":"triage started"}'
```

## Provenance Trace

```bash
providapt_api "$PROVIDAPT_URL/api/v1/investigation/report?pid=1234&direction=backward&depth=5"
providapt_api "$PROVIDAPT_URL/api/v1/graph/export" > graph.json
```

## Policy Draft, Diff, and Publish

```bash
providapt_api "$PROVIDAPT_URL/api/v1/control/policies"
providapt_api -X POST "$PROVIDAPT_URL/api/v1/control/policies" \
  -H "Content-Type: application/json" \
  -d '{"action":"validate","draft":"rules: []"}'
```

## Support Bundle

```bash
providapt_api -X POST "$PROVIDAPT_URL/api/v1/control/support" \
  -H "Content-Type: application/json" \
  -d '{"action":"prepare","note":"customer escalation"}'
providapt_api "$PROVIDAPT_URL/api/v1/control/support/download" -o support-bundle.tar.gz
```
