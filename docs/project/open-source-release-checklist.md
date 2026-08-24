# Open Source Release Checklist

This checklist turns the engineering release into a public, operator-ready open-source delivery.

## Release Ownership

| Area | Required Owner | Release Responsibility |
| --- | --- | --- |
| Engineering | Engineering lead | Build, tests, release artifacts, rollback plan |
| Security | Security lead | Vulnerability review, hardening posture, disclosure readiness |
| Legal | Legal / project owner | Open-source license, notices, privacy, trademark guidance |
| Maintainers | Maintainer lead | Support bundle workflow, issue triage, release notes |

## Operator-Facing Package

- Release notes and changelog describe operator-visible changes.
- Installation and upgrade paths are documented for source, package, container, and Helm deployments.
- Linux service installation, uninstall, and upgrade preflight are documented at `docs/getting-started/install.md`.
- Policy publish and rollback actions expose deployment plan status; agent-side pull/apply acknowledgements are included in telemetry for centralized configuration enforcement.
- Fleet group/tag metadata and policy history persist across control-plane restarts.
- Telemetry acknowledgements include the desired policy version so agents can expose policy drift before full remote apply is implemented.
- Evaluation guide is available at `docs/getting-started/evaluation.md`.
- Supported platforms, kernel prerequisites, and known limitations are explicit.
- Air-gapped delivery and offline artifact verification instructions are ready when required.
- Release artifact requirements are tracked in `docs/project/release-artifact-matrix.md`.

## Artifact Readiness

- Binaries, packages, container images, Helm chart, and SBOM are generated from the same tag.
- `checksums.txt` is generated and signed.
- Version, commit, and build date are embedded in released binaries.
- Artifact verification instructions work on a clean host.
- Package lifecycle hooks follow `docs/developer/package-build.md`.
- Vulnerability scan results are attached to the release evidence or explicitly waived.

## Support Readiness

- Support intake channel is active and monitored.
- Security reporting channel is active and monitored.
- Support expectations exist for lab, production, and community users.
- Support bundle redaction defaults are reviewed.
- Escalation path exists for kernel/eBPF compatibility issues.
- Support severity, response targets, and runbooks are tracked in `docs/project/support-sla.md`.

## Maintainer Readiness

- Demo scenario is scripted and repeatable.
- POC success criteria are documented.
- Sizing guidance covers small, medium, and large deployments.
- Limitations are understood by maintainers and operator-facing teams.
- Lab-to-production handoff checklist is available.
- Operator handoff and validation success criteria are tracked in `docs/project/operator-handoff.md`.
- Production readiness, sizing, RBAC, SIEM, backup/restore, and policy lifecycle guidance are published under `docs/project/` and `docs/user-guide/`.

## Final Open Source Gate

Do not publish an open-source release until:

- `docs/project/release-evidence-v1.2.3-rc.1.md` or the final version-specific evidence file is filled in.
- `docs/developer/release-readiness.md` has no open release-blocking items.
- Engineering, security, legal, and maintainer owners approve.
- Final approvals are recorded in `docs/project/release-approval-record.md`.
- Known limitations and accepted risks are documented.
