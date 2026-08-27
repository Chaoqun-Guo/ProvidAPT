# VM Release Evidence: Dashboard Policy Split And Soak Check

Date: 2026-08-27

## Scope

This evidence records the Dashboard policy JavaScript split, latest VM browser
baseline, capture/enrichment evidence, and the current 24-hour soak readiness
state after deploying the latest open-source build.

## Build And Deployment

| Item | Value |
| --- | --- |
| Commit | `f58a485` |
| Binary | `build/bin/providaptd` |
| SHA-256 | `d42f12226ef15c87dcc33c25c11645436e6f1700892d263cc62471d262f0d93c` |
| Control URL | redacted lab control-plane URL |

Deployed lab nodes:

| Lab Node | Result |
| --- | --- |
| control node | active, commit `f58a485` |
| worker node A | active, commit `f58a485` |
| worker node B | active, commit `f58a485` |

## Verification

| Check | Result | Evidence |
| --- | --- | --- |
| Go tests | pass | `go test ./...` |
| Lint | pass | `golangci-lint run`, 0 issues |
| Dashboard JS syntax | pass | `node --check` across Dashboard JS assets |
| VM fleet | pass | `/tmp/providapt-vm-fleet-f58a485/vm-fleet-verification.json` |
| Open-source residue | pass | `/tmp/providapt-vm-open-source-residue-f58a485/vm-open-source-residue.json` |
| New policy asset | pass | `GET /assets/dashboard-policy.js` returned 200 |
| Trace SVG stress | pass | `/tmp/providapt-trace-stress-f58a485/trace-svg-stress.json` |
| Browser visual baseline | pass | `/tmp/providapt-visual-regression-f58a485/visual-regression-snapshots.json` |
| Visual gate | pass | `/tmp/providapt-visual-regression-f58a485/visual-regression-gate.json` |
| Capture enrichment | pass | `/tmp/providapt-vm-capture-f58a485/capture-enrichment-field-gate.json` |
| 24-hour soak readiness | blocked | `/tmp/providapt-soak-f58a485/soak-readiness.json` |

Dashboard DOM assertions passed for all required browser viewports:

| Viewport | Horizontal Overflow | Element Overflow | Text Overflow | View Menu Covered |
| --- | ---: | ---: | ---: | --- |
| `390x844` | 0 | 0 | 0 | no |
| `1366x768` | 0 | 0 | 0 | no |
| `1920x1080` | 0 | 0 | 0 | no |
| `2560x1080` | 0 | 0 | 0 | no |

Capture/enrichment field gate passed on real VM event evidence:

| Field | Coverage |
| --- | ---: |
| `cmdline` | 99.98% |
| `event_type` | 100.0% |
| `exe_path` | 99.98% |
| `gid` | 100.0% |
| `network_tuple` | 100.0% |
| `pathname` | 100.0% |
| `pid` | 100.0% |
| `ppid` | 99.99% |
| `uid` | 100.0% |

## Soak Status

The 24-hour soak readiness gate remains blocked for the latest deployed build.
The VM fleet had been running for more than 24 hours, but deploying this commit
restarted `providapt.service`, so the current daemon runtime evidence does not
yet satisfy a continuous 24-hour window for commit `f58a485`.

Current soak gate summary:

| Check | Status | Observed | Budget |
| --- | --- | ---: | ---: |
| samples | pass | 2 | 1 |
| hosts | pass | 1 | 1 |
| duration | blocked | 0.0661 h | 24 h |
| cpu | pass | 0.0% | 25.0% |
| memory | pass | 10.544 MiB | 512.0 MiB |
| disk | pass | 0.0 MiB | 4096.0 MiB |
| drops | pass | 0 | 0 |

Worker nodes are covered by fleet and capture evidence. They do not expose a
local REST status endpoint on port 18080 in this deployment shape, so soak
sampling currently records the control-plane node only.

## Notes

- Dashboard policy loading, drilldowns, mutation validation, and policy actions
  now live in `dashboard-policy.js`.
- The main Dashboard script is reduced to 1995 lines after the policy split.
- The soak sampler now uses `uptime_seconds` from `/api/v1/status` when an
  explicit start epoch is not supplied, avoiding zero-duration samples for live
  daemon status payloads.
