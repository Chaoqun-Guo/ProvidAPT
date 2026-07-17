# Release Evidence - v1.2.2

Date: 2026-07-17
Release: `v1.2.2`
Status: Release candidate evidence captured

This file records the evidence required before publishing or handing off a commercial ProvidAPT release candidate.

## Release Identity

| Item | Value |
| --- | --- |
| Release tag | `v1.2.2` |
| Commit SHA | Current release candidate branch; final SHA is recorded by CI after push |
| Build host / runner | Local Windows host with Linux Docker release build |
| Go version | `1.25.0` via toolchain auto-download in Linux Docker |
| Kernel used for loader validation | Deferred to privileged VM validation |

## Validation Evidence

| Gate | Command / Source | Result | Evidence Location |
| --- | --- | --- | --- |
| eBPF build | `BUILD_EBPF=0 make release-commercial` | Accepted limitation for userspace/package release candidate | `dist/release-readiness.md` |
| userspace build | `make release-commercial` | PASS | `dist/release-readiness.md` |
| Go tests | `go test ./pkg/controlplaneha ./pkg/api ./pkg/config ./pkg/releasecheck ./cmd/cli/providapt-sign` | PASS | Local validation log |
| Go vet | Release-scoped CI gate | Scheduled for remote CI after push | `.github/workflows/ci.yml` |
| lint | Release-scoped CI gate | Scheduled for remote CI after push | `.github/workflows/lint.yml` |
| loader smoke | Privileged VM validation | Deferred to VM deployment phase | `docs/developer/release-readiness.md` |
| UTF-8 check | `python scripts/verify-utf8.py` | PASS | Local validation log |

## Artifact Evidence

| Artifact | Required Check | Result |
| --- | --- | --- |
| Linux binaries | version, commit, build date embedded | PASS |
| `.deb` package | install, config check, uninstall | PASS |
| `.rpm` package | install, config check, uninstall | PASS |
| tarball | extraction and executable CLI smoke | PASS |
| Docker image | image labels, startup, health endpoint | Scheduled for P1/P2 CI and VM validation |
| Helm chart | archive generated and included in checksums | PASS |
| SBOM | SPDX and CycloneDX generated | PASS with minimal fallback SBOM; full Syft SBOM required in CI release environment |
| checksums | `checksums.txt` generated and signed | PASS with `providapt-sign` Ed25519 signature |

## Commercial Approval

| Area | Owner | Status | Notes |
| --- | --- | --- | --- |
| Product | Product owner | Candidate accepted | Customer-visible scope documented |
| Security | Security owner | Candidate accepted with follow-up | Full vulnerability scan report required before customer handoff |
| Legal | Legal owner | Documentation prepared | Final EULA/DPA review remains an external approval activity |
| Support | Support owner | Candidate accepted | SLA and handoff materials prepared |
| Sales engineering | Sales engineering owner | Candidate accepted | POC and onboarding material prepared |

## Known Limitations

- eBPF build and privileged loader smoke require a Linux host with kernel headers and elevated capabilities; they are deferred to VM validation.
- Local release generation used minimal SBOM fallbacks when Syft was unavailable in the transient Docker build container; CI is configured to use pinned Syft/Grype/Trivy versions for full release evidence.
- Docker image and Helm runtime smoke are scheduled for CI/VM validation before customer handoff.

## Final Decision

- Release decision: Candidate accepted for CI, VM deployment, and final approval validation
- Approver: Engineering release owner
- Decision date: 2026-07-17
