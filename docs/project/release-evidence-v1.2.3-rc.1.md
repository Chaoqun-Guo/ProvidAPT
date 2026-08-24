# Release Evidence - v1.2.3-rc.1

Date: 2026-07-19
Release: `v1.2.3-rc.1`
Status: Release candidate evidence captured

This file records the evidence required before publishing or handing off the `v1.2.3-rc.1` ProvidAPT release candidate.

## Release Identity

| Item | Value |
| --- | --- |
| Release tag | `v1.2.3-rc.1` |
| Commit evidence | `6e459ff0-worktree` |
| Build host / runner | Ubuntu VM `192.168.150.132` |
| Go version | `1.25.12` |
| Kernel used for eBPF build | Ubuntu 6.8 BPF-capable validation host |

## Validation Evidence

| Gate | Command / Source | Result | Evidence Location |
| --- | --- | --- | --- |
| eBPF build | `BUILD_EBPF=1 GO_TAGS=bpf make release-open-source` | PASS: BPF objects compiled and packaged | `dist/release-readiness.md` |
| userspace build | Go `1.25.12` Linux build with `GO_TAGS=bpf` | PASS: daemon and CLI binaries built with real BPF loader | `dist/release-readiness.md` |
| Go vulnerability scan | `govulncheck -tags=bpf ./...` | PASS: no reachable vulnerabilities found | `build/security/govulncheck.txt` |
| package smoke | `PACKAGE_SMOKE_MODE=host make package-smoke-matrix` | PASS: Debian install/config/remove/purge, RPM metadata/extract, tarball executable check | `build/package-smoke/` |
| release readiness | `providaptctl -release-check` through `make release-open-source` | PASS: release signoff ready | `dist/release-readiness.md` |

## Artifact Evidence

| Artifact | Required Check | Result |
| --- | --- | --- |
| Linux binaries | version, commit evidence, build date embedded | PASS |
| `.deb` package | install, config check, remove, purge | PASS on Ubuntu host-mode smoke |
| `.rpm` package | metadata and extraction smoke | PASS on Ubuntu host-mode smoke |
| tarball | extraction and executable CLI smoke | PASS |
| Helm chart | archive generated and included in checksums | PASS |
| monitoring bundle | Prometheus, Alertmanager, Grafana, and Ansible bundle generated and included in checksums | PASS |
| SBOM | SPDX and CycloneDX generated | PASS with Go module fallback, 164 inventory entries |
| checksums | `checksums.txt` generated and signed | PASS with `providapt-sign` Ed25519 signature |
| vulnerability scan | govulncheck reachable-code scan | PASS: no reachable vulnerabilities found |

## Known Limitations

- This candidate was built from the current working tree and records commit evidence as `6e459ff0-worktree`; create a clean commit and rebuild before immutable public publication.
- Grype and Trivy were unavailable in the Linux rerun environment because Docker registry / Docker socket access was unavailable; Security approval is required if govulncheck-only evidence is accepted.
- Container image archive was not generated. For air-gapped Docker handoff, rerun with `BUILD_CONTAINER=1 REQUIRED_ARTIFACTS=archive,deb,rpm,helm,monitoring,container`.
- Deployment-specific CORS origins, TLS certificates, SIEM tokens, and encryption keys must be replaced before production deployment.

## Final Decision

- Release decision: Candidate ready for external approval review and customer handoff preparation
- Approver: Engineering release owner
- Decision date: 2026-07-19
