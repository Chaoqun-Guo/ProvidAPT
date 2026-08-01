# Changelog

All notable changes to ProvidAPT are documented here.

## v1.2.3-rc.1 (2026-07-19)

### Added

- Added commercial release handoff evidence for `v1.2.3-rc.1`, including release evidence, security scan summary, external approval request, and a hardened production configuration template.
- Added monitoring bundle validation to the release artifact matrix and release readiness workflow.
- Added host-mode package smoke testing for Debian, RPM, and tarball artifacts.

### Changed

- Upgraded the release toolchain baseline to Go `1.25.12`.
- Expanded commercial release checks to require archive, Debian, RPM, Helm, and monitoring artifacts by default.
- Updated eBPF event ABI documentation to match the current 340-byte raw event layout.

### Security

- Added `govulncheck` reachable-code vulnerability scanning to the commercial release script.
- Rebuilt the release candidate with Go `1.25.12`; the Linux rerun reported no reachable vulnerabilities.
- Recorded Grype/Trivy as pending external Security waiver or rerun because Docker registry / socket access was unavailable in the rerun environment.
## v1.2.2 (2026-06-09)

### Fixed

- Fixed `golangci-lint` workflow failure by upgrading from `v2.0` to `v2.12.2` in
  `.github/workflows/lint.yml`, resolving the `unknown flag: --fix` regression
  introduced by golangci-lint v2 API changes
- Fixed Go version inconsistency in `ci.yml` -`GO_VERSION` now matches across
  all workflows (`"1.25"`)
- Upgraded `anchore/sbom-action` from `@v0` to `@v1` for Node 24 compatibility
  in the release pipeline

### Added

- Added `.editorconfig` for consistent editor settings across the project
- Added `.gitattributes` for consistent line-ending handling (LF for sources,
  binary markers for images/archives)
- Added `scripts/verify-utf8.py` for automated UTF-8 encoding verification
- Added `docs/project/encoding-policy.md` documenting the project's encoding
  conventions
- Added `examples/` directory with usage examples:
  - `examples/README.md`
  - `examples/client-status/main.go` -API client example
  - `examples/config/providapt.local.toml` -annotated local config
  - `examples/provql/queries.sql` -example Provenance Query Language queries
  - `examples/supportbundle-api/README.md` -support bundle API walkthrough

### Changed

- Expanded and reorganized project documentation with clearer release-scoped
  sections
- Formatted `internal/policy/mgmt/server.go` to resolve code style issues
- Updated project documentation to reflect current project state and release
  target

## v1.2.1 (2026-06-09)

### Added

- Commercial control-plane workflows for fleet management, RBAC, policy operations, alert workflow, support bundle export, license validation, and upgrade preflight
- Persistent audit coverage for support, policy, alert, fleet, license, and upgrade actions
- Release-scoped project documentation, including project layout and release consistency evidence

### Changed

- Build and test entry points now use release-neutral target names such as `make build-core`, `make build-ebpf`, and `make test-core`
- Deployment defaults, installer examples, and Helm/Terraform/Ansible manifests now point to `v1.2.1`
- Legacy version-labelled wording was removed from documentation, scripts, and user-facing output

### Fixed

- Node 24 compatibility in GitHub Actions release and lint workflows
- Local `golangci-lint v2` issues across release-scoped packages
- Documentation drift between release notes, roadmap, progress log, and release workflow assets

For implementation detail and engineering notes, see `docs/developer/changelog.md`.
