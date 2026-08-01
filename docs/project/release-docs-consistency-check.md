# Release Docs Consistency Check

Date: 2026-08-01
Release: `v1.2.3-rc.1`

## Scope Checked

- `README.md`
- `docs/INDEX.md`
- `CHANGELOG.md`
- `docs/developer/INDEX.md`
- `docs/developer/changelog.md`
- `docs/developer/release-notes-v1.2.3-rc.1.md`
- `docs/developer/release-readiness.md`
- `docs/project/documentation-audit.md`
- `docs/project/commercial-release-checklist.md`
- `docs/project/release-evidence-v1.2.3-rc.1.md`
- `docs/project/release-security-scan-summary-v1.2.3-rc.1.md`
- `docs/project/external-approval-request-v1.2.3-rc.1.md`
- `docs/project/macbook-ai-development-handoff.md`
- `docs/project/project-layout.md`
- `.github/workflows/release.yml`

## Verified Alignment

- Current release-candidate identifier is consistently `v1.2.3-rc.1` in customer-facing entry points
- Build/test command references use current Makefile targets.
- Deployment, release evidence, handoff, and approval examples align with
  `v1.2.3-rc.1` or intentionally documented historical release evidence.
- Release notes, changelog, and workflow files describe the same release train

## Open Editorial Notes

- Historical `v1.2.1` and `v1.2.2` release notes remain for traceability
- Historical release evidence remains under `docs/project/` when it records a
  candidate decision or security scan summary.
- Short-lived local validation snapshots should not be kept as root-level docs;
  fold current state into `docs/project/macbook-ai-development-handoff.md` or a
  release evidence record.

## Current Gate Documentation Coverage

- Visual regression: `make visual-regression-snapshots`, `make visual-regression-gate`
- Capture/enrichment coverage: `make capture-enrichment-field-gate`
- Artifact signing: `make artifact-signing-gate`
- Activation server: `make activation-server-gate`
- Policy approval: `make policy-approval-gate`
- Backup readiness: `make backup-readiness-gate`
- Support bundle: `make support-bundle-gate`
- Deployment diagnostics: `make deployment-diagnostics-gate`
