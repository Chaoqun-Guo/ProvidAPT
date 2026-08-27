# Release Notes - v1.2.1

Date: 2026-06-09
Status: Ready for release
Version: `v1.2.1`

## Summary

This release moves ProvidAPT into a cleaner open-source-release posture by aligning release automation, product documentation, deployment defaults, and release-scoped quality gates.

## Highlights

### Open-Source Control Plane

- Fleet inventory and metadata management
- Role-based access control for `admin`, `analyst`, and `auditor`
- Policy publication and rollback workflow skeletons
- Alert workflow actions and delivery visibility

### Operational Safety

- Support bundle export, redaction, retention, and audit visibility
- Persistent audit records for support, fleet, policy, alert, and upgrade operations
- Ticketing integration paths for Jira, generic webhook, and ServiceNow

### Upgrade Controls

- Upgrade download, checksum verification, signature verification, preflight, and rollback-plan tracking

### Release Engineering and Documentation

- Node 24-compatible GitHub Actions workflows
- Release-neutral build targets (`build-core`, `build-ebpf`, `build-userspace`, `install-local`, `test-core`)
- Project documentation restructured under `docs/project/`

## Validation Snapshot

- Local `golangci-lint` passes with `0 issues` for release-scoped packages
- Release-scoped Go package tests pass locally
- Documentation references were reviewed and aligned to `v1.2.1`

## Operator Actions

Before rollout, confirm:

- trusted-header role mappings
- artifact signing public key, checksum, and verification policy
- upgrade download URL, expected SHA256, signature path, and rollback plan
- support bundle retention and redaction settings
