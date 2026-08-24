# Developer Changelog

This file records engineering-facing milestones for the current maintained release line.

## v1.2.3-rc.1 (2026-07-19)

### Release Engineering

- Added `govulncheck` reachable-code vulnerability scanning to `scripts/release/open-source-release.sh`.
- Required archive, Debian, RPM, Helm, and monitoring artifacts by default for open-source readiness.
- Added host-mode package smoke testing for limited Linux validation hosts without Docker.
- Upgraded the release build baseline to Go `1.25.12` and documented the security scan rerun.
- Added release evidence, security scan summary, external approval request, and production configuration templates for operator handoff.

### Validation

- `govulncheck -tags=bpf ./...` on the Linux rerun host reported no reachable vulnerabilities.
- Host-mode package smoke passed for Debian install/config/remove/purge, RPM metadata/extraction, and tarball executable checks.
- Release readiness reported release signoff ready with 16 passed checks, 0 warnings, 0 waived, and 0 failed.
## v1.2.2 (2026-06-09)

### Release Engineering

- Fixed `golangci-lint` workflow `unknown flag: --fix` by upgrading from `v2.0` to `v2.12.2`
- Fixed Go version drift in `ci.yml` (was `"1.22"`, now `"1.25"` to match other workflows)
- Upgraded `anchore/sbom-action` from `@v0` to `@v1` for Node 24 compatibility
- Added `.editorconfig`, `.gitattributes`, and `scripts/verify-utf8.py` for encoding hygiene
- Added `examples/` directory with API client, config, ProvQL, and support-bundle walkthroughs
- Cleaned up stale local test cache directories (`.tmp-*`)

### Validation

- Local `golangci-lint` passes with `0 issues` on release-scoped packages
- `go test ./...` passes locally
- `python scripts/verify-utf8.py` passes

## v1.2.1 (2026-06-09)

### Product and Operations

- Added fleet, policy, alert, support-bundle, and upgrade control-plane workflows suitable for open-source operations
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
