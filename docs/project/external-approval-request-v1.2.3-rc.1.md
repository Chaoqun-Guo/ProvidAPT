# External Approval Request - v1.2.3-rc.1

Date: 2026-07-19
Release candidate: `v1.2.3-rc.1`
Commit evidence: `6e459ff0-worktree`

## Requested Decisions

| Area | Requested Decision | Evidence |
| --- | --- | --- |
| Product | Approve scope, customer-visible value, and known limitations | `docs/project/release-evidence-v1.2.3-rc.1.md` |
| Security | Approve govulncheck results and decide whether the Grype/Trivy waiver is acceptable | `docs/project/release-security-scan-summary-v1.2.3-rc.1.md` |
| Legal | Approve Apache-2.0 license, DPA, privacy notice, third-party notices, and trademark readiness | `docs/project/open-source-release-checklist.md` |
| Support | Approve SLA, support bundle workflow, and escalation readiness | `docs/project/support-sla.md` |
| Sales Engineering | Approve POC flow, sizing, onboarding, and customer handoff readiness | `docs/project/customer-handoff.md` |

## Approval Outcomes

| Area | Approver | Decision | Notes |
| --- | --- | --- | --- |
| Product | named product owner | approve or reject | External owner required |
| Security | named security owner | approve, reject, or request waiver | Must accept govulncheck-only evidence or request Grype/Trivy rerun |
| Legal | named legal owner | approve or reject | External owner required |
| Support | named support owner | approve or reject | External owner required |
| Sales Engineering | named SE owner | approve or reject | External owner required |

## Engineering Recommendation

- Engineering readiness: approved for release-candidate review.
- Publication recommendation: do not publish as a final immutable release until external approvals are recorded and the working tree is committed/rebuilt.
- Delivery recommendation: regenerate `build/handoff/providapt-v1.2.3-rc.1-handoff.zip` from the current commit and validate it with `providaptctl -release-check -release-handoff` before reviewer delivery.
