# Developer Changelog

This file keeps a concise engineering-facing history of major product milestones.

## v1.2.1 (2026-06-08)

### Product and Operations

- Added commercial control-plane capabilities for fleet inventory, RBAC, policy publication skeletons, alert workflow actions, and delivery history
- Added support bundle management with archive redaction, retention cleanup, download control, and persistent audit visibility
- Added license inspection with expiry, grace-period, revocation, and signature validation
- Added upgrade download and preflight workflows with checksum verification, signature validation, and rollback-plan tracking

### Release Engineering

- Added `docs/developer/release-readiness.md` as the final release gate
- Added `docs/DOCUMENTATION_AUDIT.md` as a document navigation classifier
- Added `docs/RELEASE_DOCS_CONSISTENCY_CHECK.md` for release review evidence
- Cleaned release-facing documentation entry points and normalized Chinese index pages to UTF-8

### Validation

- Verified scoped Go package tests for config and API paths
- Verified Linux cross-compilation for `cmd/agent/daemon`
- Cleaned transient build/test artifacts before release review

## v1.1.0 (2026-06-03)

### Added

- eBPF inspection CLI via `providaptctl -bpf`
- data validation and repair tooling via `providaptctl -verify`
- persistent audit logging framework in `pkg/audit/`
- loader fallback handling for CO-RE and BPF LSM failures
- fuzz-testing coverage for parsing and query paths

### Improved

- broader package test coverage across transport, secure, plugin, threat intel, graph query, hardware acceleration, and support bundle paths
- BPF stats JSON parsing reliability in profiling collection
