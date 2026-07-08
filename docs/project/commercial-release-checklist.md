# Commercial Release Checklist

This checklist turns the engineering release into a customer-ready commercial delivery.

## Release Ownership

| Area | Required Owner | Release Responsibility |
| --- | --- | --- |
| Product | Product lead | Scope, customer-visible value, known limitations |
| Engineering | Engineering lead | Build, tests, release artifacts, rollback plan |
| Security | Security lead | Vulnerability review, hardening posture, disclosure readiness |
| Legal | Legal / business owner | EULA, DPA, notices, trademarks, customer terms |
| Support | Support lead | SLA, escalation paths, support bundle workflow |
| Sales engineering | SE lead | POC plan, demo flow, sizing guidance, onboarding material |

## Customer-Facing Package

- Release notes and changelog describe customer-visible changes.
- Installation and upgrade paths are documented for source, package, container, and Helm deployments.
- Evaluation guide is available at `docs/getting-started/evaluation.md`.
- Supported platforms, kernel prerequisites, and known limitations are explicit.
- Air-gapped delivery instructions and offline license process are ready when required.

## Artifact Readiness

- Binaries, packages, container images, Helm chart, and SBOM are generated from the same tag.
- `checksums.txt` is generated and signed.
- Version, commit, and build date are embedded in released binaries.
- Artifact verification instructions work on a clean host.
- Vulnerability scan results are attached to the release evidence or explicitly waived.

## Support Readiness

- Support intake channel is active and monitored.
- Security reporting channel is active and monitored.
- SLA definitions exist for trial, standard, and enterprise customers.
- Support bundle redaction defaults are reviewed.
- Escalation path exists for kernel/eBPF compatibility issues.

## Sales Engineering Readiness

- Demo scenario is scripted and repeatable.
- POC success criteria are documented.
- Sizing guidance covers small, medium, and large deployments.
- Competitive positioning and limitations are understood by customer-facing teams.
- Trial-to-production handoff checklist is available.

## Final Commercial Gate

Do not publish a commercial release until:

- `docs/project/release-evidence-v1.2.2.md` is filled in.
- `docs/developer/release-readiness.md` has no open release-blocking items.
- Product, engineering, security, legal, support, and sales engineering owners approve.
- Known limitations and accepted risks are documented.
