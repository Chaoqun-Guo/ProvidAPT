# Changelog

All notable changes to ProvidAPT are documented here.

This changelog follows a curated, release-oriented format inspired by Keep a Changelog.

## v1.2.0 (2026-06-08)

### Added

- Commercial control-plane workflows for fleet management, RBAC, policy operations, alert workflow, support bundle export, license validation, and upgrade preflight
- Persistent audit coverage for support, policy, alert, fleet, license, and upgrade actions
- Support bundle archive redaction, retention control, controlled download, and audit visibility
- License status inspection with expiry, grace period, revocation, and signature verification
- Upgrade readiness inspection with package checksum, signature verification, download, preflight, and rollback plan tracking
- Documentation audit, release-readiness checklist, and release-doc consistency review

### Changed

- Release-facing documentation entry points were normalized and cleaned for GA review
- Core Chinese documentation index pages were rewritten as clean UTF-8 entry points
- README navigation now better reflects product, operator, and developer release paths

### Security

- Remote license revocation feeds support signature verification and cache fallback
- Upgrade validation supports detached signature verification and release-oriented preflight checks
- Support bundles default to redaction-friendly handling and controlled access patterns

### Operational Notes

- Use `docs/developer/release-readiness.md` as the final release gate
- Use `docs/DOCUMENTATION_AUDIT.md` as the documentation navigation index during release review
- Artifact names and packaged outputs follow the `v1.2.0` release tag

## v1.1.0 (2026-06-03)

### Added

- `providaptctl -bpf` for eBPF program, capability, and pinned-map inspection
- `providaptctl -verify` for data validation and optional repair workflows
- Persistent admin audit logging via `pkg/audit/`
- eBPF loader fallback from CO-RE/LSM to kprobe mode with audit visibility
- Expanded fuzz coverage for event parsing, config loading, taint matching, and query parsing

### Improved

- Test coverage across graph query, transport, secure, plugin, threat intel, hardware acceleration, and support bundle paths
- JSON parsing in BPF profiling collection

For older feature-history details, see `docs/developer/changelog.md`.
