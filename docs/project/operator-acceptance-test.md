# Operator Acceptance Test

This document defines a practical acceptance test for an open-source ProvidAPT deployment.

## Scope

Run these checks in an operator-approved staging or lab validation environment before production rollout.

## Acceptance Matrix

| Area | Test | Pass Criteria | Evidence |
| --- | --- | --- | --- |
| Installation | Install package or deploy container/Helm chart | Service starts without manual patching | install log, `systemctl status`, or deployment status |
| Configuration | Validate operator config | `providaptctl -config-check` passes | command output |
| Fleet | Register at least one server and two agents | Agents appear in `Agent Overview` with fresh report age | dashboard screenshot or API response |
| Capture | Generate process, file, and network activity | Events appear in graph export and investigation views | graph JSON or SVG |
| Alerts | Trigger a safe sample rule | Alert appears in Alert Workflow | alert ID and workflow state |
| Provenance | Open trace SVG and Markdown report | Trace contains process, file, network, and timeline context | exported report |
| Policy | Validate, diff, publish, and rollback a test policy | Approval and audit records are created | audit log and policy diff |
| SIEM | Send or queue a test event | Delivery succeeds or outbox records retry state | SIEM event or outbox file |
| Support | Generate support bundle | Bundle downloads with secrets redacted | support bundle archive |
| Backup | Run backup and restore dry run | Backup artifact is created and restore plan is documented | backup log |
| Security | Confirm TLS, CORS, network controls, and secret handling | No sample secrets remain in production config | redacted config review |

## Sample Test Events

```bash
curl -fsS https://example.com -o /tmp/providapt-cat.out
cat /tmp/providapt-cat.out >/dev/null
rm -f /tmp/providapt-cat.out
```

## Required Signoff

| Role | Decision |
| --- | --- |
| Operator owner | accept / reject |
| Security owner | accept / reject |
| Operations owner | accept / reject |
| Maintainers | accept / reject |
| ProvidAPT release owner | accept / reject |

## Exit Criteria

- All release-blocking tests pass.
- Any production or detection issues have owner, severity, workaround, and target date.
- Production secrets are injected through the operator's secret-management process.
- Release approvals are recorded in the release approval record.
