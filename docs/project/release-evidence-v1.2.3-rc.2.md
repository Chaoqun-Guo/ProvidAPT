# Release Evidence - v1.2.3-rc.2

Release: `v1.2.3-rc.2`

This file records the evidence gathered for the open-source `v1.2.3-rc.2`
release candidate.

## Release Identity

| Field | Value |
| --- | --- |
| Release tag | `v1.2.3-rc.2` |
| Commit SHA | `666fee21f1cf4bc665f8e8dbc539fb8e903cf20f` |
| Build date | `2026-08-28T03:31:02Z` |
| Build type | Open-source control plane |
| Authentication mode | No API key, license key, or activation workflow |

## Validation Evidence

| Area | Status | Evidence |
| --- | --- | --- |
| Dashboard duty flow | `pass` | `docs/project/vm-release-evidence-2026-08-28-dashboard-duty-flow.md` |
| VM fleet health | `pass` | 3 healthy agents, expected commit verified |
| Open-source residue | `pass` | No API key/auth/activation residue found on VM fleet |
| Browser visual baseline | `pass` | Dashboard and Trace Viewer, 8/8 screenshot matrix |
| Release security scans | `pass` | `docs/project/release-security-scan-summary-v1.2.3-rc.2.md` |
| Artifact signing | `pass` | `checksums.txt` signed with ProvidAPT Ed25519 signature format |
| SBOM generation | `pass` | SPDX and CycloneDX SBOMs generated |
| Release readiness | `pass` | 16 checks passed, 0 warnings, 0 failures |
| Handoff bundle | `pass` | Candidate handoff zip references current release and commit |

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
| `providapt_v1.2.3-rc.2_amd64.deb` | `8b74a10fdde1b510720438da556ff4f2bc87cfa020c2fd88ee2f777bfa6a1f06` |
| `providapt-1.2.3-rc.2.x86_64.rpm` | `30e1290fb049ee3652842048c9e0384fbd79631f75688e3aa0696206d5313505` |
| `providapt-helm-v1.2.3-rc.2.tgz` | `b87b23cff84eecacd9ff69f0ea2a5a3ef66509b5b81cda5ee5acb0885d4c7734` |
| `providapt-monitoring-v1.2.3-rc.2.tgz` | `448629bffef22c7e751dee004ab3a6d047362573ed6c3d396c009ba90ee6b424` |
| `providapt-v1.2.3-rc.2-linux-amd64.tar.gz` | `831ba62756b24b97d57d0e1db1fbe00ce2f1cfc613d91b6307dbbfd22482c8e7` |
| `sbom.cdx.json` | `c470605e38ab112b76f5879bddcc4f0f7d2f4942cb414613882cc59d33a505ae` |
| `sbom.spdx.json` | `31eb1678a53e3d5991b2f5d95630c81d3f4f0e43577556070212d2f9ac683d28` |

## Release Notes

- Dashboard operator path was simplified to `Today -> Triage -> Trace -> Act`.
- Low-frequency release, backup, upgrade, and compliance evidence remains in
  secondary workspaces.
- The open-source control plane has no Dashboard API key prompt, activation
  server flow, license key flow, or local API policy denial banner.
- The VM browser baseline passed at mobile, 1366x768, 1920x1080, and ultrawide
  viewport sizes.

## Remaining Candidate Limitations

- Local candidate artifacts were generated without rebuilding eBPF objects
  because the macOS release host lacks a Linux BTF/vmlinux.h build environment.
  The final immutable release should rebuild eBPF objects on a Linux builder or
  CI runner before publication.
- Product, Security, Legal, Support, and Maintainer approvals still need named
  reviewer signoff before final `v1.2.3`.
- Model lifecycle evidence still requires real long-window baseline, drift
  report, and promotion approval.
- Plugin distribution still requires the real signing policy, compatibility
  policy, permission model, and rollback drill evidence.
