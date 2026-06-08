# Release Notes Draft

Date: 2026-06-08
Status: Ready for GA / release candidate packaging
Version: v1.2.1

## Summary

This release moves ProvidAPT from a strong engineering base toward a commercially operable product. The focus is on control-plane readiness, operational auditability, release safety, and documentation quality.

## Highlights

### 1. Commercial Control Plane

- Fleet inventory, group/tag metadata management, and multi-agent overview
- Minimal RBAC with `admin`, `analyst`, and `auditor` roles
- Policy-center MVP with publish and rollback skeletons
- Alert workflow actions including dedup, mute, assignment, close/reopen, and delivery visibility

### 2. Operational Safety

- Support bundle export, archive download, redaction, retention, and audit history
- Persistent audit trail for support, fleet, policy, alert, license, and upgrade operations
- Ticketing integration skeletons for Jira, generic webhook, and ServiceNow

### 3. Release and License Controls

- License inspection with expiry, grace period, revocation, and signature verification
- Remote revocation feed support with cache fallback and verification status
- Upgrade package download, checksum verification, signature verification, preflight, and rollback-plan tracking

### 4. Documentation and Release Readiness

- Release checklist in `docs/developer/release-readiness.md`
- Documentation classifier in `docs/DOCUMENTATION_AUDIT.md`
- Release consistency evidence in `docs/RELEASE_DOCS_CONSISTENCY_CHECK.md`
- Cleaned README and normalized key Chinese documentation index pages to UTF-8

## Operator Impact

Operators should review and set the following before rollout:

- license public key / revocation feed settings
- upgrade download URL, expected SHA256, signature path, and rollback plan
- support bundle retention and redaction settings
- API key role mappings for `admin`, `analyst`, and `auditor`

## Validation Snapshot

- Scoped Go tests for config and API flows passed during release preparation
- Linux cross-compilation for `cmd/agent/daemon` passed during release preparation
- Release-facing documentation entry points were reviewed and cleaned

## Known Limitations

- Some older historical documents still need editorial normalization
- A final production rollout should still include Linux-host execution of `loader-smoke` when kernel-loader paths are part of the release

## Suggested GA Announcement Blurb

ProvidAPT now includes a commercial-grade control-plane foundation with operational auditability, safer release workflows, support bundle handling, and release-oriented license and upgrade validation.
