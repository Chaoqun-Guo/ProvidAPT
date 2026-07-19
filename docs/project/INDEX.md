# Project Documentation

This section collects engineering documentation for repository governance, layout, release consistency, and commercial delivery.

## Documents

| Document | Description |
| --- | --- |
| [project-layout.md](project-layout.md) | Repository structure, ownership boundaries, and placement conventions |
| [documentation-audit.md](documentation-audit.md) | Documentation inventory by audience and purpose |
| [encoding-policy.md](encoding-policy.md) | UTF-8 and mojibake prevention policy |
| [release-docs-consistency-check.md](release-docs-consistency-check.md) | Pre-release documentation consistency record |
| [release-evidence-v1.2.2.md](release-evidence-v1.2.2.md) | Release evidence template for `v1.2.2` |
| [release-evidence-v1.2.3-rc.1.md](release-evidence-v1.2.3-rc.1.md) | Release candidate evidence for `v1.2.3-rc.1` |
| [commercial-release-checklist.md](commercial-release-checklist.md) | Commercial release delivery checklist |
| [release-artifact-matrix.md](release-artifact-matrix.md) | Required commercial release artifacts and verification rules |
| [release-security-scan-summary-v1.2.2.md](release-security-scan-summary-v1.2.2.md) | Security scan evidence for v1.2.2 |
| [release-security-scan-summary-v1.2.3-rc.1.md](release-security-scan-summary-v1.2.3-rc.1.md) | Security scan evidence for the v1.2.3 release candidate |
| [external-approval-request-v1.2.3-rc.1.md](external-approval-request-v1.2.3-rc.1.md) | External approval request packet for the v1.2.3 release candidate |
| [security-waiver.md](security-waiver.md) | Security waiver template for incomplete release security controls |
| [final-release-runbook.md](final-release-runbook.md) | Final release commit, tag, build, scan, sign, publish, and rollback runbook |
| [customer-acceptance-test.md](customer-acceptance-test.md) | Customer acceptance test plan and pass criteria |
| [production-readiness.md](production-readiness.md) | Production deployment readiness checklist |
| [sizing-guide.md](sizing-guide.md) | Initial capacity planning guidance for agents, control plane, and PostgreSQL |
| [third-party-notices.md](third-party-notices.md) | Third-party notice and SBOM review template |
| [export-control.md](export-control.md) | Export-control workflow for international commercial delivery |
| [support-sla.md](support-sla.md) | Support severity, SLA, and escalation model |
| [customer-handoff.md](customer-handoff.md) | POC, onboarding, and production handoff checklist |
| [commercial-approval-record.md](commercial-approval-record.md) | Final commercial release approval record |

## Usage Guidance

1. Review `project-layout.md` before adding new documents.
2. Use `documentation-audit.md` to find the right documentation entry point.
3. Run the checks in `release-docs-consistency-check.md` before release.
4. Complete the release evidence, artifact matrix, handoff checklist, SLA, and approval record before commercial delivery.
