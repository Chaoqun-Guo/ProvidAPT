# Commercial Approval Record

This record captures the local release-blocking closure for a controlled release-candidate handoff. GitHub Actions evidence is intentionally excluded from this run by release-owner instruction and must be attached before public publication.

## Release Candidate

| Field | Value |
| --- | --- |
| Release | current `git describe --tags --always` at release build time |
| Commit SHA | recorded in `dist/release-readiness.md` and `build/release-gate-status.json` |
| Evidence date | generated at release build time |
| Evidence report | `dist/release-readiness.md` |
| Artifact bundle | `dist/` |
| Waiver record | `build/release-waivers.json` |
| Scope | controlled VM validation and internal release-candidate handoff |

## Approval Areas

| Area | Required Evidence | Approver | Decision |
| --- | --- | --- | --- |
| Product | scope, value, limitations, roadmap impact | Release Engineering delegate | approved_with_risk |
| Engineering | build, tests, install, upgrade, rollback | Release Engineering delegate | approved |
| Security | vulnerability review, hardening, disclosure readiness | Release Engineering delegate | approved_with_risk |
| Legal | notices, privacy, trademark and license handoff review | Release Engineering delegate | approved_with_risk |
| Support | SLA, escalation, support bundle workflow | Release Engineering delegate | approved_with_risk |
| Sales engineering | POC plan, demo, sizing, onboarding | Release Engineering delegate | approved_with_risk |

## Accepted Risks

| Risk | Impact | Mitigation | Owner | Expiry |
| --- | --- | --- | --- | --- |
| GitHub Actions evidence is intentionally excluded from this release-blocking run | Public release cannot rely on this record alone | Attach authenticated GitHub Actions evidence before public publication | Release Engineering | Before public publication |
| Grype and Trivy source scans are waived for this local run | Source and filesystem vulnerability evidence is incomplete | Run scanners in approved CI or security workstation before unrestricted release | Release Engineering / Security | 2026-08-10 |
| Customer API keys, TLS certificates, license files, CORS origins, SIEM tokens, and encryption keys are environment-specific | Default artifacts cannot be deployed unchanged to production | Replace values during deployment with customer secret management and rerun operational readiness checks | Customer deployment owner | Before production rollout |
| Real external owner signatures are not attached to this local evidence file | This record is valid only for controlled internal or customer-validation handoff | Replace delegate decisions with named Product, Security, Legal, Support, and Sales Engineering approvals for GA/public release | Release owner | Before GA/public release |

## Final Decision

- Decision: approved_with_risk for controlled release-candidate handoff
- Release owner: Release Engineering delegate
- Decision date: 2026-07-27
- Publication constraint: do not publish as GA/public release until CI evidence, scanner evidence or security-approved waivers, and named external owner signoffs are attached.
