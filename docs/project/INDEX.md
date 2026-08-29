# Project Documentation

This section collects engineering documentation for repository governance, layout, release consistency, and open-source delivery.

## Documents

| Document | Description |
| --- | --- |
| [project-layout.md](project-layout.md) | Repository structure, ownership boundaries, and placement conventions |
| [documentation-audit.md](documentation-audit.md) | Documentation inventory by audience and purpose |
| [encoding-policy.md](encoding-policy.md) | UTF-8 and mojibake prevention policy |
| [release-docs-consistency-check.md](release-docs-consistency-check.md) | Pre-release documentation consistency record |
| [macbook-ai-development-handoff.md](macbook-ai-development-handoff.md) | Current development handoff, implemented gates, and remaining work |
| [release-evidence-v1.2.2.md](release-evidence-v1.2.2.md) | Release evidence template for `v1.2.2` |
| [release-evidence-v1.2.3-rc.1.md](release-evidence-v1.2.3-rc.1.md) | Release candidate evidence for `v1.2.3-rc.1` |
| [release-evidence-v1.2.3-rc.2.md](release-evidence-v1.2.3-rc.2.md) | Release candidate evidence for the open-source `v1.2.3-rc.2` tag |
| [vm-release-evidence-2026-08-24.md](vm-release-evidence-2026-08-24.md) | Three-VM open-source cleanup, Trace SVG, visual, and capture evidence |
| [vm-release-evidence-2026-08-26.md](vm-release-evidence-2026-08-26.md) | Three-VM evidence after Dashboard panel-template split |
| [vm-release-evidence-2026-08-26-dashboard-js.md](vm-release-evidence-2026-08-26-dashboard-js.md) | Three-VM evidence after Dashboard JavaScript asset split |
| [vm-release-evidence-2026-08-28-dashboard-duty-flow.md](vm-release-evidence-2026-08-28-dashboard-duty-flow.md) | VM browser baseline for the simplified Dashboard duty-flow interface |
| [vm-release-evidence-2026-08-29-open-source-release.md](vm-release-evidence-2026-08-29-open-source-release.md) | GitHub prerelease publication and latest VM validation evidence |
| [open-source-release-checklist.md](open-source-release-checklist.md) | Open-source release delivery checklist |
| [release-artifact-matrix.md](release-artifact-matrix.md) | Required open-source release artifacts and verification rules |
| [release-security-scan-summary-v1.2.2.md](release-security-scan-summary-v1.2.2.md) | Security scan evidence for v1.2.2 |
| [release-security-scan-summary-v1.2.3-rc.1.md](release-security-scan-summary-v1.2.3-rc.1.md) | Security scan evidence for the v1.2.3 release candidate |
| [release-security-scan-summary-v1.2.3-rc.2.md](release-security-scan-summary-v1.2.3-rc.2.md) | Security scan evidence for the open-source v1.2.3-rc.2 release candidate |
| [security-scan-waiver-summary.md](security-scan-waiver-summary.md) | Summary of accepted scan waivers and closure expectations |
| [external-approval-request-v1.2.3-rc.1.md](external-approval-request-v1.2.3-rc.1.md) | External approval request packet for the v1.2.3 release candidate |
| [security-waiver.md](security-waiver.md) | Security waiver template for incomplete release security controls |
| [final-release-runbook.md](final-release-runbook.md) | Final release commit, tag, build, scan, sign, publish, and rollback runbook |
| [operator-acceptance-test.md](operator-acceptance-test.md) | Operator acceptance test plan and pass criteria |
| [production-readiness.md](production-readiness.md) | Production deployment readiness checklist |
| [sizing-guide.md](sizing-guide.md) | Initial capacity planning guidance for agents, control plane, and PostgreSQL |
| [third-party-notices.md](third-party-notices.md) | Third-party notice and SBOM review template |
| [export-control.md](export-control.md) | Export-control workflow for international open-source delivery |
| [support-sla.md](support-sla.md) | Support severity, SLA, and escalation model |
| [operator-handoff.md](operator-handoff.md) | Lab validation, onboarding, and production handoff checklist |
| [release-approval-record.md](release-approval-record.md) | Final open-source release approval record |
| [open-source-readiness-gap-register.md](open-source-readiness-gap-register.md) | Prioritized open-source readiness gap register |

## Usage Guidance

1. Review `project-layout.md` before adding new documents.
2. Use `../INDEX.md` and `documentation-audit.md` to find the right documentation entry point.
3. Run the checks in `release-docs-consistency-check.md` before release.
4. Complete the release evidence, artifact matrix, handoff checklist, SLA, and approval record before open-source delivery.
5. Run `make release-evidence-manifest REQUIRE_EVIDENCE=1` to generate a
   hash-indexed manifest for release evidence files before final handoff.
