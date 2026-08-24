# Release Approval Record

This record captures release-blocking closure for an open-source release candidate. GitHub Actions evidence, security scan evidence, artifact checksums, SBOMs, and maintainer approval must be attached before public publication.

## Release Candidate

| Field | Value |
| --- | --- |
| Release | current `git describe --tags --always` at release build time |
| Commit SHA | recorded in `dist/release-readiness.md` and `build/release-gate-status.json` |
| Evidence date | generated at release build time |
| Evidence report | `dist/release-readiness.md` |
| Artifact bundle | `dist/` |
| Waiver record | `build/release-waivers.json` |
| Scope | open-source release candidate validation |

## Approval Areas

| Area | Required Evidence | Approver | Decision |
| --- | --- | --- | --- |
| Engineering | build, tests, install, upgrade, rollback | _pending_ | _pending_ |
| Security | vulnerability review, hardening, disclosure readiness | _pending_ | _pending_ |
| Legal / project owner | Apache-2.0 license, notices, privacy, trademark guidance | _pending_ | _pending_ |
| Maintainers | support workflow, issue triage, release notes, community handoff | _pending_ | _pending_ |

## Accepted Risks

| Risk | Impact | Mitigation | Owner | Expiry |
| --- | --- | --- | --- | --- |
| GitHub Actions evidence is intentionally excluded from this release-blocking run | Public release cannot rely on this record alone | Attach authenticated GitHub Actions evidence before public publication | Release Engineering | Before public publication |
| Grype and Trivy source scans are waived for this local run | Source and filesystem vulnerability evidence is incomplete | Run scanners in approved CI or security workstation before unrestricted release | Release Engineering / Security | 2026-08-10 |
| TLS certificates, CORS origins, SIEM tokens, and encryption keys are environment-specific | Default artifacts cannot be deployed unchanged to production | Replace values during deployment with approved secret management and rerun operational readiness checks | Deployment owner | Before production rollout |
| Named owner approvals are not attached yet | This record is not sufficient for a public release | Replace pending decisions with named Engineering, Security, Legal/project-owner, and Maintainer approvals | Release owner | Before public release |

## Final Decision

- Decision: pending
- Release owner: _pending_
- Decision date: _pending_
- Publication constraint: do not publish until CI evidence, scanner evidence or security-approved waivers, final artifact evidence, and named owner approvals are attached.
