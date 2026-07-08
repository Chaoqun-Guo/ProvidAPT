# Release Evidence - v1.2.2

Date: 2026-06-09
Release: `v1.2.2`
Status: Evidence template

This file records the evidence required before publishing or handing off a commercial ProvidAPT release candidate.

## Release Identity

| Item | Value |
| --- | --- |
| Release tag | `v1.2.2` |
| Commit SHA | _fill before release_ |
| Build host / runner | _fill before release_ |
| Go version | `1.25` |
| Kernel used for loader validation | _fill before release_ |

## Validation Evidence

| Gate | Command / Source | Result | Evidence Location |
| --- | --- | --- | --- |
| eBPF build | `make build-ebpf` | _pending_ | _attach log_ |
| userspace build | `make build-userspace` | _pending_ | _attach log_ |
| Go tests | `go test ./...` or release-scoped CI set | _pending_ | _attach log_ |
| Go vet | `go vet ./...` or release-scoped CI set | _pending_ | _attach log_ |
| lint | `golangci-lint v2.12.2` release-scoped packages | _pending_ | _attach log_ |
| loader smoke | `sudo make loader-smoke` | _pending_ | _attach log_ |
| UTF-8 check | `python scripts/verify-utf8.py` | _pending_ | _attach log_ |

## Artifact Evidence

| Artifact | Required Check | Result |
| --- | --- | --- |
| Linux binaries | version, commit, build date embedded | _pending_ |
| `.deb` package | install, service start, uninstall | _pending_ |
| `.rpm` package | install, service start, uninstall | _pending_ |
| tarball | checksum verification and smoke run | _pending_ |
| Docker image | image labels, startup, health endpoint | _pending_ |
| Helm chart | render, install, uninstall, default values review | _pending_ |
| SBOM | SPDX and CycloneDX generated | _pending_ |
| checksums | `checksums.txt` generated and signed | _pending_ |

## Commercial Approval

| Area | Owner | Status | Notes |
| --- | --- | --- | --- |
| Product | _fill_ | _pending_ | Customer-visible scope approved |
| Security | _fill_ | _pending_ | Vulnerability and hardening review complete |
| Legal | _fill_ | _pending_ | EULA, DPA, notices, contacts reviewed |
| Support | _fill_ | _pending_ | SLA, escalation, support bundle flow approved |
| Sales engineering | _fill_ | _pending_ | POC, demo, sizing, onboarding material ready |

## Known Limitations

- _fill with any accepted release limitations or explicit waivers_

## Final Decision

- Release decision: _pending_
- Approver: _fill_
- Decision date: _fill_
