# Release Evidence - v1.2.3

Release: `v1.2.3`

This file records the final open-source release evidence for `v1.2.3`.

## Release Identity

| Field | Value |
| --- | --- |
| Release tag | `v1.2.3` |
| Commit SHA | `0ba72be5db90e9877e9025cb6d7774e4095c468f` |
| GitHub release | <https://github.com/Chaoqun-Guo/ProvidAPT/releases/tag/v1.2.3> |
| Build type | Open-source control plane |
| Control-plane mode | Open-source build with previous restricted-access gates removed |
| eBPF build source | Ubuntu Linux VM builder with kernel BTF/vmlinux.h |
| RPM build source | Ubuntu Linux VM `rpmbuild` from a minimal release-only staging bundle |

## Validation Evidence

| Area | Status | Evidence |
| --- | --- | --- |
| Final tag | `pass` | Annotated tag `v1.2.3` points at `0ba72be5db90e9877e9025cb6d7774e4095c468f` |
| VM fleet health | `pass` | 3 healthy agents verified during final release validation |
| Open-source residue | `pass` | No legacy restricted-access residue found on VM fleet |
| Browser visual baseline | `pass` | Dashboard and Trace Viewer baseline covered mobile, 1366x768, 1920x1080, and ultrawide |
| Capture enrichment | `pass` | VM NDJSON evidence showed required field coverage above gate thresholds |
| Trace SVG stress | `pass` | Real alert/layout stress evidence passed latency budget |
| Artifact signing | `pass` | `checksums.txt` signed with ProvidAPT Ed25519 signature format |
| SBOM generation | `pass` | SPDX and CycloneDX SBOMs generated from the final release tree |
| Release readiness | `pass` | 16 checks passed, 0 warnings, 0 failures after final RPM and handoff inclusion |
| Release security scans | `pass` | `docs/project/release-security-scan-summary-v1.2.3.md` |
| Handoff bundle | `pass` | Final handoff zip references current release and commit |
| GitHub publication | `pass` | Final Release `v1.2.3` published as a stable, non-prerelease GitHub Release |

## Artifact Matrix

| Artifact | Status |
| --- | --- |
| Linux archive | `generated` |
| Debian package | `generated` |
| RPM package | `generated` |
| Helm chart archive | `generated` |
| Monitoring bundle | `generated` |
| SPDX SBOM | `generated` |
| CycloneDX SBOM | `generated` |
| SHA-256 checksum manifest | `generated` |
| Checksum signature | `generated` |
| Handoff bundle | `generated` |

## Artifact Hashes

| Artifact | SHA-256 |
| --- | --- |
| `providapt_v1.2.3_amd64.deb` | `e5d9c5641e5bb1447a0ffdded1ea1bb8cc2031ba3515472ece94c80ffc10383a` |
| `providapt-1.2.3.x86_64.rpm` | `0036cb42685f444266954b280e0e73cced00e8b85b230181acb11abce15438a8` |
| `providapt-helm-v1.2.3.tgz` | `d3004d491755936ab762aebea1ab11658cc90bbe6caab56259cf9198b1f586a1` |
| `providapt-monitoring-v1.2.3.tgz` | `15c400d27cc7822b6d61f2298bd76782f7d1d41a52883ab78d8917733a14db82` |
| `providapt-v1.2.3-linux-amd64.tar.gz` | `89b0b5e7af6a3c55f66fac9833e06ced063d0112a4b13db41cd7116c86d45cf8` |
| `sbom.cdx.json` | `3a12fcad1f610cd6664cf26d0a49beadccd799b590019ee91c1742aaea94b399` |
| `sbom.spdx.json` | `afe633b725365e9e82a933cb427ac20b576761c84bd78aee839ab4c9eb27c4ce` |

## Notes

- The final release line is fully open-source; previous restricted-access gates are not part of this release.
- VM-specific hostnames, private endpoints, and credentials are intentionally excluded from this public evidence file.
- Deployment-specific CORS origins, TLS material, SIEM tokens, and encryption keys must be supplied by each operator environment.

## Remaining Release Closure

- Archive final CI status, security scan manifest, artifact signing gate, and handoff bundle metadata with the release.
- Named human approvals remain outside the repository automation and must be recorded by maintainers.
