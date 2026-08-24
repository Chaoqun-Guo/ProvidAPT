# Release Notes - v1.2.3-rc.1

Date: 2026-07-19
Status: Release candidate
Version: `v1.2.3-rc.1`

## Summary

`v1.2.3-rc.1` is a open-source release candidate focused on release evidence, vulnerability scanning, package smoke testing, production configuration readiness, and operator handoff material.

This candidate is ready for external Product, Security, Legal, Support, and Maintainer review. It should not be published as an immutable final release until those approvals are recorded and the candidate is rebuilt from a clean release commit.

## Added

- Release evidence for `v1.2.3-rc.1` in `docs/project/release-evidence-v1.2.3-rc.1.md`.
- Security scan summary in `docs/project/release-security-scan-summary-v1.2.3-rc.1.md`.
- External approval request packet in `docs/project/external-approval-request-v1.2.3-rc.1.md`.
- Hardened production configuration template in `examples/config/providapt.production.yaml`.
- Monitoring bundle validation for open-source release readiness.
- Host-mode package smoke testing for Debian, RPM, and tarball artifacts.

## Changed

- Open-source release checks now require archive, Debian, RPM, Helm, and monitoring artifacts by default.
- The release toolchain baseline is Go `1.25.12`.
- Release artifact validation now verifies that release evidence references the current version and commit evidence.
- The raw eBPF event ABI documentation now matches the current 340-byte event layout.

## Security

- Added `govulncheck` reachable-code scanning to the open-source release pipeline.
- Rebuilt the release candidate with Go `1.25.12`; the Linux rerun reported no reachable vulnerabilities.
- Grype and Trivy scans were not completed in the rerun environment because Docker registry / Docker socket access was unavailable. Security must either rerun those tools in an approved environment or explicitly approve the govulncheck-only evidence for the target delivery.

## Validation

- `govulncheck -tags=bpf ./...`: passed with no reachable vulnerabilities.
- Host-mode package smoke: passed for Debian install/config/remove/purge, RPM metadata/extraction, and tarball executable checks.
- `providaptctl -release-check`: release signoff ready with 16 passed checks, 0 warnings, 0 waived, and 0 failed.

## Known Limitations

- External approvals must be recorded in `docs/project/release-approval-record.md` before final publication.
- The candidate evidence records `6e459ff0-worktree`; rebuild from a clean release commit before final public publication.
- Container image archive was not generated in the rerun. Generate it with `BUILD_CONTAINER=1` if the target delivery requires air-gapped Docker artifacts.
