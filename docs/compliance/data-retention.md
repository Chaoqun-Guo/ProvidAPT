# Data Retention

This document defines retention guidance for ProvidAPT operational data. Final retention values must be approved by the customer and legal/compliance owners.

## Data Classes

| Data Class | Examples | Default Owner | Retention Guidance |
| --- | --- | --- | --- |
| raw events | process, file, network provenance events | Security Operations | shortest period that supports investigation |
| alerts | alert workflow records and triage notes | Security Operations | customer incident-retention policy |
| audit records | admin actions, policy changes, support downloads | Compliance / Security | compliance requirement, often 180-365 days |
| support bundles | diagnostic archives | Support | delete after case closure unless evidence hold applies |
| SIEM outbox | queued delivery payloads | Security Operations | delete after confirmed delivery or expiry |

## Configuration

```yaml
compliance:
  retention_days: 365
  max_audit_entries: 20000
  report_dir: /var/log/providapt/compliance

backup:
  enabled: true
  interval: 24h
  retain_archives: 7
```

## Deletion and Export

- Export required evidence before retention cleanup.
- Record retention changes in the audit log.
- Delete support bundles containing sensitive diagnostics after the approved support window.
- Confirm SIEM export before removing local outbox payloads.

## Legal Hold

Suspend deletion for affected data when the customer declares legal hold or active incident preservation requirements.
