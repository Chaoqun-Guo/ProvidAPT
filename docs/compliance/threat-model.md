# Threat Model

This document summarizes primary threats and controls for ProvidAPT deployments.

## Assets

- kernel event stream and eBPF objects
- agent identity and telemetry channel
- control-plane dashboard and API
- PostgreSQL control-plane state
- local event and evidence stores
- SIEM tokens and delivery outbox
- release artifacts, SBOMs, checksums, and signatures

## Trust Boundaries

```text
Kernel / host boundary
  -> agent userspace
  -> network telemetry boundary
  -> control plane
  -> PostgreSQL and local evidence stores
  -> external SIEM, ticketing, and support systems
```

## Threats and Controls

| Threat | Impact | Controls |
| --- | --- | --- |
| compromised agent host | forged or missing telemetry | mTLS/API auth, enrollment state, report-age monitoring, audit review |
| unauthorized dashboard access | policy or evidence manipulation | TLS, network ACLs, RBAC roles, trusted-header SSO only behind controlled proxy |
| policy tampering | reduced detection coverage | policy diff, approvals, audit records, rollback |
| evidence deletion | investigation loss | backups, retention policy, support bundle export, audit trail |
| SIEM token exposure | unauthorized event injection or read | secret management, token rotation, outbox controls |
| supply-chain compromise | malicious artifact deployment | SBOM, checksums, signatures, vulnerability scans, release approvals |
| excessive event volume | dropped events or resource exhaustion | capture filters, backpressure, retention tuning, sizing review |

## Review Cadence

- Review before each major release.
- Review after authentication, storage, SIEM, or policy-engine changes.
- Review during customer production readiness assessment.
