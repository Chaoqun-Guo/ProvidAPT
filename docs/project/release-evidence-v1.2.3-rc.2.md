# Release Evidence - v1.2.3-rc.2

Release: `v1.2.3-rc.2`

This file records the evidence gathered for the open-source `v1.2.3-rc.2`
release candidate.

## Release Identity

| Field | Value |
| --- | --- |
| Release tag | `v1.2.3-rc.2` |
| Commit SHA | `666fee21f1cf4bc665f8e8dbc539fb8e903cf20f` |
| Build date | `2026-08-28T08:28:43Z` |
| Build type | Open-source control plane |
| GitHub release | <https://github.com/Chaoqun-Guo/ProvidAPT/releases/tag/v1.2.3-rc.2> |
| Control-plane mode | Open-source build with legacy closed-source access gates removed |
| eBPF build source | Ubuntu Linux VM builder with kernel BTF/vmlinux.h |

## Validation Evidence

| Area | Status | Evidence |
| --- | --- | --- |
| Dashboard duty flow | `pass` | `docs/project/vm-release-evidence-2026-08-28-dashboard-duty-flow.md` |
| VM fleet health | `pass` | 3 healthy agents, expected commit verified |
| Open-source residue | `pass` | No legacy closed-source access-gate residue found on VM fleet |
| Browser visual baseline | `pass` | Dashboard and Trace Viewer, 8/8 screenshot matrix |
| Release security scans | `pass` | `docs/project/release-security-scan-summary-v1.2.3-rc.2.md` |
| Artifact signing | `pass` | `checksums.txt` signed with ProvidAPT Ed25519 signature format |
| SBOM generation | `pass` | SPDX and CycloneDX SBOMs generated |
| Release readiness | `pass` | 16 checks passed, 0 warnings, 0 failures |
| Handoff bundle | `pass` | Candidate handoff zip references current release and commit |
| eBPF artifact coverage | `pass` | Archive, Debian, and RPM packages include 6 `.bpf.o` objects |

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
| `providapt_v1.2.3-rc.2_amd64.deb` | `5e49a6b6db0efe91e535cf0e4fae7e33ca5a312b56dc1a35cd1fb122c6e50936` |
| `providapt-1.2.3-rc.2.x86_64.rpm` | `818e7e171a8bb95dbf7e619433b736454345fdfa2d5a81006370bbffe703dc02` |
| `providapt-helm-v1.2.3-rc.2.tgz` | `7741c4eb44dd0fadcf1a3528559ba5adb32326d029f2363f78c87db787363ed4` |
| `providapt-monitoring-v1.2.3-rc.2.tgz` | `2a3dbde304a6a067d83fb453447e114131354da18769a2aa8eaa3d96f9b0ae6c` |
| `providapt-v1.2.3-rc.2-linux-amd64.tar.gz` | `f84cb132c3df8fd5e210d226d0ca8e149b7852d2bf964e1cc1e98e9a50371385` |
| `sbom.cdx.json` | `e390ba98458d8014e7a052fc9a748cc40eeb61dc249f3e5c38d29e45a54bd0b2` |
| `sbom.spdx.json` | `f4387ccd07fea4576f562cbac68f5cd9343af425d4ecc38da422df95cba6a9e5` |

## eBPF Object Hashes

| Object | SHA-256 |
| --- | --- |
| `deception.bpf.o` | `97cec35deaa3bd69c04b071a2b12b47ecab8c5536add0b805367337519b41fc0` |
| `defense.bpf.o` | `e017be89e32a812ba4e95f58cd4580264ee2c6914a76e8fa2edf2e74b0231015` |
| `kprobe_fallback.bpf.o` | `333e2c2e999a25ce7edff9b5f69b43699ddcc46f6b3bb4dff0280719e4f93e83` |
| `lsm_hooks.bpf.o` | `f7ffa0f4dc27c8d97bfe0a8590f1835148af70f626a22f010f4779bb40b8d6ba` |
| `memory.bpf.o` | `59263a3bb35d3420cabf580f7b81eb283d923495198b5d77724d961159b98b46` |
| `network.bpf.o` | `d367ffe097765d3be58f3ed737f0661fa3bbcfcdb6801652e75b30f9020c8920` |

## Release Notes

- Dashboard operator path was simplified to `Today -> Triage -> Trace -> Act`.
- Low-frequency release, backup, upgrade, and compliance evidence remains in
  secondary workspaces.
- The open-source control plane has no legacy closed-source access gate, product
  gating flow, or removed access-denial banner.
- The VM browser baseline passed at mobile, 1366x768, 1920x1080, and ultrawide
  viewport sizes.

## Remaining Candidate Limitations

- Product, Security, Legal, Support, and Maintainer approvals still need named
  reviewer signoff before final `v1.2.3`.
- Model lifecycle evidence still requires real long-window baseline, drift
  report, and promotion approval.
- Plugin distribution still requires the real signing policy, compatibility
  policy, permission model, and rollback drill evidence.
