# Commercial Approval Record

Use this record for the final release meeting before publishing or customer delivery.

## Release Candidate

| Field | Value |
| --- | --- |
| Release | `v1.2.3-rc.1` |
| Commit SHA | `6e459ff0-worktree` |
| Build date | `2026-07-19T01:23:22Z` |
| Evidence report | `dist/release-readiness.md` |
| Artifact bundle | `dist/` |
| Known limitations | `docs/project/release-evidence-v1.2.3-rc.1.md` |

## Approval Areas

| Area | Required Evidence | Approver | Decision |
| --- | --- | --- | --- |
| Product | scope, value, limitations, roadmap impact | external owner required | requires approval |
| Engineering | build, tests, install, upgrade, rollback | engineering release owner | approved_with_risk |
| Security | vulnerability review, hardening, disclosure readiness | external owner required | requires waiver: govulncheck passed; Grype/Trivy unavailable |
| Legal | EULA, DPA, notices, privacy, trademarks | external owner required | requires approval |
| Support | SLA, escalation, support bundle workflow | external owner required | requires approval |
| Sales engineering | POC plan, demo, sizing, onboarding | external owner required | requires approval |

## Decision Rules

- `approved`: release can be published or delivered.
- `approved_with_risk`: release can proceed only with documented accepted risks.
- `blocked`: release cannot proceed until blockers are closed.

## Accepted Risks

| Risk | Impact | Mitigation | Owner | Expiry |
| --- | --- | --- | --- | --- |
| Final customer API keys, TLS certificates, license files, CORS origins, SIEM tokens, and encryption keys are environment-specific | Default artifacts cannot be deployed unchanged to production | Replace all customer-specific values during deployment using `examples/config/providapt.production.yaml` and customer secret management | Customer deployment owner | Before production rollout |
| Grype/Trivy source scans were unavailable in the Linux rerun | Security evidence is incomplete for unrestricted public publication | Use `docs/project/release-security-scan-summary-v1.2.3-rc.1.md` for govulncheck evidence and run Grype/Trivy later or record an approved Security waiver | Security owner | Before public release |
| Container image archive was not generated in the Linux rerun | Air-gapped bundle is incomplete if a Docker image handoff is required | Re-run with `BUILD_CONTAINER=1 REQUIRED_ARTIFACTS=archive,deb,rpm,helm,monitoring,container` for offline customers | Engineering release owner | Before air-gapped handoff |

## Final Decision

- Decision: blocked until required external approvals are recorded
- Release owner: engineering release owner
- Decision date: 2026-07-19
