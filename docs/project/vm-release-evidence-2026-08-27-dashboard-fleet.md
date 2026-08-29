# VM Release Evidence: Dashboard Fleet Split

Date: 2026-08-27

## Scope

This evidence records the Dashboard fleet JavaScript split and the follow-up VM
browser baseline for the simplified Dashboard information architecture.

## Build And Deployment

| Item | Value |
| --- | --- |
| Commit | `ef7f629` |
| Binary | `build/bin/providaptd` |
| SHA-256 | `af10d47757e3b9e9fa69706ee3702a9cc39aa2198bfd80ef8fe1d562349a53ac` |
| Control URL | redacted lab control-plane URL |

Deployed hosts:

| Lab Node | Result |
| --- | --- |
| control node | active, commit `ef7f629` |
| worker node A | active, commit `ef7f629` |
| worker node B | active, commit `ef7f629` |

## Verification

| Check | Result | Evidence |
| --- | --- | --- |
| Go tests | pass | `go test ./...` |
| Lint | pass | `golangci-lint run`, 0 issues |
| Dashboard JS syntax | pass | `node --check` across Dashboard JS assets |
| VM fleet | pass | `/tmp/providapt-vm-fleet-ef7f629/vm-fleet-verification.json` |
| Open-source residue | pass | `/tmp/providapt-vm-open-source-residue-ef7f629/vm-open-source-residue.json` |
| New fleet asset | pass | `GET /assets/dashboard-fleet.js` returned 200 |
| Trace SVG stress | pass | `/tmp/providapt-trace-stress-ef7f629/trace-svg-stress.json` |
| Browser visual baseline | pass | `/tmp/providapt-visual-regression-ef7f629/visual-regression-snapshots.json` |
| Visual gate | pass | `/tmp/providapt-visual-regression-ef7f629/visual-regression-gate.json` |

Dashboard DOM assertions passed for all required browser viewports:

| Viewport | Horizontal Overflow | Element Overflow | Text Overflow | View Menu Covered |
| --- | ---: | ---: | ---: | --- |
| `390x844` | 0 | 0 | 0 | no |
| `1366x768` | 0 | 0 | 0 | no |
| `1920x1080` | 0 | 0 | 0 | no |
| `2560x1080` | 0 | 0 | 0 | no |

Trace SVG stress used three discovered VM alert IDs, redacted from this public
evidence note. All four layouts passed for each alert; latency p95 was
`99.93` ms.

## Notes

- Dashboard fleet inventory, enrollment, and environment actions now live in
  `dashboard-fleet.js`.
- The main Dashboard script is reduced to 2302 lines after the fleet split.
- VM validation confirms the new asset route is public in the open-source
  control plane and does not reintroduce legacy closed-source access prompts.
