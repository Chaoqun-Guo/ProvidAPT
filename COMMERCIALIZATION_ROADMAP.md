# Commercialization Roadmap

Last Updated: `2026-06-09`
Release Line: `v1.2.2`

## Goal

ProvidAPT has completed the core product-hardening work needed for the `v1.2.2` release line. The next phase focuses on turning the current release-ready engineering baseline into a repeatable commercial delivery model.

## Current Status

### Completed Foundation

- Core build flow standardized around `make build-core`, `make build-ebpf`, `make build-userspace`, and `make install-local`
- Release-facing documentation aligned to `v1.2.2`
- Installer, Helm, Terraform, and Ansible defaults aligned to `v1.2.2`
- Control-plane APIs for support bundles, license checks, upgrade readiness, policy management, alert workflow, and delivery recovery are in place
- Local release-quality validation completed with `go test ./...`, `go vet ./...`, and doc consistency review
- CI workflows updated for current GitHub Actions runtime expectations

### Product Readiness Assessment

| Area | Status | Notes |
|------|--------|-------|
| Core detection and provenance pipeline | Ready | Stable build and test baseline |
| Packaging and deployment | Ready | Docker, Helm, Terraform, Ansible available |
| Operator documentation | Ready | Install, deploy, CLI, manual, release docs refreshed |
| Release engineering | Ready | Release notes, changelog, workflow alignment complete |
| Commercial control plane | In progress | APIs available; UX and lifecycle polish continue |
| Enterprise integrations | In progress | Ticketing and workflow primitives exist; broader ecosystem support remains |

## P0 Priorities

These items are considered release-blocking or immediate post-release hardening work.

1. Keep release metadata synchronized with Git tags, manifests, installer defaults, and changelog entries
2. Preserve green local quality gates for `go test ./...` and `go vet ./...`
3. Maintain documentation consistency across root docs, `docs/developer/`, and deployment guides
4. Prevent regressions in support bundle, upgrade, and license-control workflows

## P1 Priorities

These items improve commercial usability and adoption without blocking the `v1.2.2` release.

1. Polish dashboard and operator workflows for fleet, alerts, support bundles, and delivery recovery
2. Expand role-based access control and audit visibility
3. Improve packaged deployment examples for air-gapped and regulated environments
4. Add more guided runbooks for incident response and post-incident review
5. Strengthen customer-facing onboarding, evaluation, and upgrade materials

## Phase Plan

### Phase 1 - Release Hardening

- Finalize release documents and validation evidence
- Keep package defaults and deployment manifests version-aligned
- Ensure project layout and documentation placement remain stable

### Phase 2 - Operator Experience

- Refine dashboard summaries and control-plane workflows
- Add clearer runbooks for support, upgrade, alert handling, and evidence export
- Reduce operator friction in day-2 operations

### Phase 3 - Commercial Scale

- Expand fleet management and multi-node operational patterns
- Improve enterprise integration depth for ticketing, delivery recovery, and audit review
- Prepare repeatable release and support motions for customer environments

## Definition of Done

The roadmap milestone is considered complete when:

- Release tag, changelog, installer, and deployment defaults all match
- Core docs are accurate, discoverable, and stored in the correct folders
- Local full validation passes without known release-blocking failures
- Release notes clearly summarize delivered value and operational impact
- The repository is clean enough for handoff, packaging, and ongoing maintenance

## Related Documents

- `DEVELOPMENT_PROGRESS.md`
- `CHANGELOG.md`
- `docs/developer/release-notes-v1.2.2.md`
- `docs/project/documentation-audit.md`
- `docs/project/release-docs-consistency-check.md`
