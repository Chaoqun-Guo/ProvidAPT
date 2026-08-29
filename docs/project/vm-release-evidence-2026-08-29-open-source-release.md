# VM Release Evidence: Open-Source Release And Follow-Up Validation

Date: 2026-08-29

This evidence records the `v1.2.3-rc.2` GitHub release publication and the
follow-up VM validation for the current open-source development head.

## Release Publication

| Item | Value |
| --- | --- |
| Published release | <https://github.com/Chaoqun-Guo/ProvidAPT/releases/tag/v1.2.3-rc.2> |
| Release tag | `v1.2.3-rc.2` |
| Release tag commit | `666fee21f1cf4bc665f8e8dbc539fb8e903cf20f` |
| Published artifacts | Linux archive, Debian package, RPM package, Helm archive, monitoring archive, SPDX SBOM, CycloneDX SBOM, checksums, checksum signature, public verification key, handoff bundle |
| Release type | GitHub prerelease |

## Follow-Up Development Head

| Item | Value |
| --- | --- |
| Deployed commit | `8913198` |
| Version string | `v1.2.3-rc.2-8-g8913198` |
| VM fleet | three-node private lab fleet |
| Log cleanup during deploy | disabled |
| Dashboard access mode | open-source control plane |

## VM Deployment Checks

| Check | Result |
| --- | --- |
| Three-node deployment | `pass` |
| Healthy agents | `3/3` |
| Expected commit | `8913198` |
| Graph elements after restart | `540` |
| Open-source residue gate | `pass` |
| Residue failures | `0` |
| Dashboard operations asset | `pass` |

## Browser Baseline

The browser baseline used real rendering against the VM-served Dashboard and a
real VM trace. Raw screenshots remain in the local run workspace and are not
committed because they can contain live operator state.

| Page | Viewport | Status | SHA-256 | Bytes | DOM |
| --- | --- | --- | --- | ---: | --- |
| `dashboard` | `390x844` | `captured` | `d15d9b11396546dcbb2da6ea904a484250dc8f2b9d5335fd9c6937dfa1133772` | 262051 | `pass` |
| `dashboard` | `1366x768` | `captured` | `bf505890876fc399cf90016a6b04363aff67c95245aa1a6f8ba0664ae4c65308` | 360640 | `pass` |
| `dashboard` | `1920x1080` | `captured` | `4025b0b4e83e800cd41ba0fb1e9474885f7c19e17719ce4d98676dafba2cb124` | 387924 | `pass` |
| `dashboard` | `2560x1080` | `captured` | `5ffc1cc8e65816d548bcd672fff4d369aa3c0cf0bc2f67545a56855d41ca1665` | 421842 | `pass` |
| `trace-viewer` | `390x844` | `captured` | `c52759435fe26669f60c7d9471597c43e862078a15399c735d2bbb66f48f2823` | 216365 | `pass` |
| `trace-viewer` | `1366x768` | `captured` | `3e3e6cc9e3b20802e82417c9039d2586df4456c5195ebb299e67d73402c8f99a` | 249794 | `pass` |
| `trace-viewer` | `1920x1080` | `captured` | `b8c71d8597ff7ecd780712f443a996ffc0a7b91093e1b35e27473d6a02fdf0d8` | 362687 | `pass` |
| `trace-viewer` | `2560x1080` | `captured` | `14ec2c3ce020caad27ad7bc5880f82bbb4da28a5187f98d0c01a7488091a0fbc` | 413229 | `pass` |

Visual regression gate status: `pass`, 8 screenshots, complete default matrix.

## Capture And Enrichment Evidence

The field gate used sampled NDJSON from all three VM hosts.

| Field | Coverage |
| --- | ---: |
| `event_type` | 100.00% |
| `pid` | 100.00% |
| `ppid` | 100.00% |
| `uid` | 100.00% |
| `gid` | 100.00% |
| `cmdline` | 99.99% |
| `exe_path` | 99.99% |
| `pathname` | 100.00% |
| `network_tuple` | 100.00% |

Event sample:

| Metric | Value |
| --- | ---: |
| Total events | 36011 |
| File events | 36000 |
| Network events | 11 |
| `file_open` | 35999 |
| `file_modify` | 1 |
| `net_connect` | 11 |

Capture/enrichment field gate status: `pass`.

## Trace SVG Stress

Trace stress used three real alert IDs from the VM control plane and all four
server-side layout modes. Alert IDs are intentionally omitted from this public
evidence note.

| Metric | Value |
| --- | ---: |
| Matrix results | 12 |
| Passing results | 12 |
| Failure count | 0 |
| Latency p50 | 1636.41 ms |
| Latency p95 | 1777.12 ms |
| Latency max | 1888.54 ms |
| Gate threshold | 3000 ms |

| Layout | Results | Pass | p50 ms | p95 ms | Max ms | Nodes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `compact` | 3 | 3 | 1634.26 | 1675.36 | 1679.93 | 14-17 |
| `grouped` | 3 | 3 | 1616.29 | 1632.99 | 1634.85 | 14-16 |
| `timeline` | 3 | 3 | 1637.97 | 1681.16 | 1685.96 | 13-17 |
| `tree` | 3 | 3 | 1656.64 | 1865.35 | 1888.54 | 13-18 |

## Notes

- The release helper now validates local artifacts before publishing to GitHub
  Releases and can run in dry-run mode.
- The remote eBPF builder was validated against the Ubuntu VM and produced all
  six `.bpf.o` objects.
- The deployment helper now keeps VM logs by default. Log removal requires
  explicitly setting `PROVIDAPT_DELETE_LOGS=1`.
- Trace SVG rendering now builds focused traces through an incident-edge index
  and exposes a short-lived SVG cache status header for diagnostics.
- Visual regression capture now retries Trace Viewer loading once before
  marking the SVG as missing, reducing flakiness on slower VM runs.
