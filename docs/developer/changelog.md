# Developer Changelog

This file records engineering-facing milestones for the current maintained release line.

## v1.2.1 (2026-06-09)

### Product and Operations

- Added fleet, policy, alert, license, support-bundle, and upgrade control-plane workflows suitable for commercial operations
- Added stronger audit coverage across control-plane mutations and operational downloads
- Added release-oriented documentation for project layout, release validation, and release notes

### Release Engineering

- Migrated GitHub Actions workflows to Node 24-compatible action versions
- Aligned lint execution with `golangci-lint v2` and a validated release package scope
- Replaced legacy build target naming with stable commands: `build-core`, `build-ebpf`, `build-userspace`, `install-local`, `test-core`

### Validation

- Local `golangci-lint` passes with `0 issues` on release-scoped packages
- Release-scoped Go package tests pass locally
- Temporary test and lint artifacts are cleaned after validation
