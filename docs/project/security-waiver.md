# Security Waiver Template

Use this document when a release cannot complete every required security scan before a controlled customer handoff.

## Waiver Request

| Field | Value |
| --- | --- |
| Release | `v1.2.3-rc.1` |
| Requested by | pending |
| Requested date | pending |
| Expiration date | pending |
| Scope | pending |
| Blocked control | pending |
| Reason | pending |

## Example Scope

For `v1.2.3-rc.1`, `govulncheck` completed successfully and reported no reachable vulnerabilities. Grype and Trivy were not completed in the rerun environment because Docker registry / Docker socket access was unavailable.

## Required Evidence

- completed scan output, such as `build/security/govulncheck.txt`
- release evidence, such as `docs/project/release-evidence-v1.2.3-rc.1.md`
- affected artifacts and versions
- reason the missing scan cannot be completed before handoff
- compensating controls
- owner and expiration date

## Compensating Controls

| Control | Owner | Status |
| --- | --- | --- |
| Run missing scanner in an approved CI or security environment | Security | pending |
| Restrict delivery to named reviewers or customer POC environment | Product / Sales Engineering | pending |
| Do not publish immutable final release until waiver is closed or approved | Release owner | pending |
| Document all known limitations in the handoff bundle | Release owner | pending |

## Approval

| Role | Approver | Decision | Date | Notes |
| --- | --- | --- | --- | --- |
| Security | pending | pending | pending | pending |
| Product | pending | pending | pending | pending |
| Release owner | pending | pending | pending | pending |

## Closure

Close the waiver when one of the following is true:

- the missing scanner is rerun successfully
- the release is rejected and not delivered
- Security approves the waiver for the exact target delivery

Record the closure decision in `docs/project/commercial-approval-record.md`.
