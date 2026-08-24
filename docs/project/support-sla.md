# Support SLA and Escalation Model

This template defines the minimum support model required before an open-source ProvidAPT release is handed to operators.

## Support Channels

| Channel | Purpose | Owner |
| --- | --- | --- |
| Support portal or email | Operator incidents, defects, and operational questions | Support lead |
| Security reporting channel | Vulnerability reports and coordinated disclosure | Security lead |
| Maintainer contact | Onboarding, adoption, and release handoff | Maintainers |
| Operator validation channel | Lab and pre-production technical validation | Maintainers |

## Severity Levels

| Severity | Definition | Initial Response | Update Cadence |
| --- | --- | --- | --- |
| Sev 1 | Production outage, data loss risk, or active compromise with ProvidAPT impact | 1 hour | every 2 hours |
| Sev 2 | Major feature degraded, fleet visibility reduced, or upgrade blocked | 4 hours | daily |
| Sev 3 | Non-critical defect, documentation gap, or integration issue | 1 business day | twice weekly |
| Sev 4 | General question or enhancement request | 3 business days | as agreed |

## Escalation Path

1. Support triages the ticket and confirms severity.
2. Support requests a redacted support bundle when needed.
3. Engineering joins for eBPF, storage, policy, upgrade, or control-plane defects.
4. Security joins for suspected compromise, vulnerability, or sensitive data exposure.
5. Product joins when a workaround changes documented behavior or accepted limitations.

## Required Runbooks

- collect and redact support bundle
- validate deployment version and supported platform
- diagnose eBPF attach or kernel compatibility failures
- recover from failed upgrade or rollback
- restore from staged checkpoint backup
- verify policy publish and rollback status
- export audit/compliance evidence
- configure Prometheus and Alertmanager routing for support escalation

## Alert Routing Deployment

Alertmanager routing is deployed by the Ansible monitoring role. Use
`deploy/ansible/examples/alertmanager-extra-vars.yml` as the starting point for
site-specific webhook URLs, then store real values in Ansible Vault or the
operator secret manager.

## Release Gate

A open-source release is support-ready only when:

- support contacts are active and monitored
- severity definitions are published to operator-facing teams
- support bundle redaction defaults are reviewed
- escalation owners are assigned
- kernel/eBPF compatibility escalation is documented
- public support expectations and escalation commitments are approved
