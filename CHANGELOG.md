# Changelog

All notable changes to ProvidAPT are documented here.

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
