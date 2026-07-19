# Release Evidence - v1.2.2

Date: 2026-07-17
Release: `v1.2.2`
Status: Release candidate evidence captured

This file records the evidence required before publishing or handing off a commercial ProvidAPT release candidate.

## Release Identity

| Item | Value |
| --- | --- |
| Release tag | `v1.2.2` |
| Commit SHA | `27ecd239` |
| Build host / runner | Local Windows host with Linux Docker release build |
| Go version | `1.25.12` via toolchain auto-download in Linux Docker |
| Kernel used for loader validation | Ubuntu 6.8 BPF LSM and CentOS 4.18 kprobe fallback VM validation |

## Validation Evidence

| Gate | Command / Source | Result | Evidence Location |
| --- | --- | --- | --- |
| eBPF build | `BUILD_EBPF=1 GO_TAGS=bpf` commercial release build | PASS: BPF objects compiled and packaged | `dist/release-readiness.md` |
| userspace build | Go 1.25 Linux Docker build with `CGO_ENABLED=0 GO_TAGS=bpf` | PASS: daemon built with real BPF loader, not stub | `dist/release-readiness.md` |
| Go tests | `go test ./pkg/controlplaneha ./pkg/api ./pkg/config ./pkg/releasecheck ./cmd/cli/providapt-sign` | PASS | Local validation log |
| Go vet | Release-scoped CI gate | Scheduled for remote CI after push | `.github/workflows/ci.yml` |
| lint | Release-scoped CI gate | Scheduled for remote CI after push | `.github/workflows/lint.yml` |
| loader smoke | Ubuntu/CentOS/server VM service deployment after `lsm=bpf` reboot | PASS | VM deployment log |
| UTF-8 check | `python scripts/verify-utf8.py` | PASS | Local validation log |

## Artifact Evidence

| Artifact | Required Check | Result |
| --- | --- | --- |
| Linux binaries | version, commit, build date embedded | PASS |
| `.deb` package | install, config check, uninstall | PASS on `ubuntu:22.04` |
| `.rpm` package | install, config check, uninstall | PASS on `rockylinux:8` |
| tarball | extraction and executable CLI smoke | PASS on `ubuntu:22.04` |
| Docker image | PostgreSQL backend service dependency | PASS on server VM with `postgres:16-alpine` |
| Helm chart | archive generated and included in checksums | PASS |
| SBOM | SPDX and CycloneDX generated | PASS with Go module fallback, 164 inventory entries |
| checksums | `checksums.txt` generated and signed | PASS with `providapt-sign` Ed25519 signature |
| vulnerability scans | source-only Grype and Trivy scans | PASS; 0 findings in `docs/project/release-security-scan-summary-v1.2.2.md` |

## Deployment Evidence

| Host | Role | Result |
| --- | --- | --- |
| `192.168.150.129` | Ubuntu agent | PASS: `lsm` includes `bpf`, LSM attachment active, `providapt.service` active, status API healthy on `:8080` |
| `192.168.150.131` | CentOS agent | PASS: `lsm` includes `bpf`, kernel 4.18 uses `kprobe_fallback`, `providapt.service` active, status API healthy on `:8080` |
| `192.168.150.132` | Ubuntu control plane/server | PASS: `lsm` includes `bpf`, LSM attachment active, `providapt.service` active, status API healthy on `:8080` |

## Commercial Approval

| Area | Owner | Status | Notes |
| --- | --- | --- | --- |
| Product | Product owner | Candidate accepted | Customer-visible scope documented |
| Security | Security owner | Candidate accepted | SBOM, checksum signature, and source scan summary generated |
| Legal | Legal owner | Documentation prepared | Final EULA/DPA review remains an external approval activity |
| Support | Support owner | Candidate accepted | SLA and handoff materials prepared |
| Sales engineering | Sales engineering owner | Candidate accepted | POC and onboarding material prepared |

## Known Limitations

- The CentOS 4.18 validation host runs in compatibility mode with `kprobe_fallback`; Linux 5.11+ remains recommended for full BPF LSM coverage.
- CI status could not be read from this workstation because GitHub CLI is not authenticated; remote CI remains the external source of truth after push.
- Customer-specific API keys, license files, CORS origins, and encryption keys must be replaced before production deployment.

## Final Decision

- Release decision: Candidate accepted for CI, VM deployment, and final approval validation
- Approver: Engineering release owner
- Decision date: 2026-07-17
