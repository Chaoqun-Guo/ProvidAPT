# VM Release Evidence: Dashboard View Menu

Date: 2026-08-26

## Scope

This evidence records the Dashboard `View` menu fix for the issue where the
opened menu could be covered by the page content on the home Dashboard.

## Build And Deployment

| Item | Value |
| --- | --- |
| Commit | `6b98ce5` |
| Binary | `build/bin/providaptd` |
| SHA-256 | `99680341efc1b0d95081816340a61f226154765b99aaac2464280205e0935fe2` |
| Control URL | `http://vm-ubuntu-master:18080` |

Deployed hosts:

| Host | Result |
| --- | --- |
| `ubuntu@vm-ubuntu-master` | active, commit `6b98ce5` |
| `centos@vm-centos-slave` | active, commit `6b98ce5` |
| `ubuntu@vm-ubuntu-slave` | active, commit `6b98ce5` |

## Verification

| Check | Result | Evidence |
| --- | --- | --- |
| Go tests | pass | `go test ./...` |
| API package tests | pass | `go test ./pkg/api` |
| Python visual regression tests | pass | `python3 -m unittest scripts.ops.visual_regression_gate_test scripts.ops.visual_regression_snapshots_test` |
| Lint | pass | `golangci-lint run`, 0 issues |
| VM fleet | pass | `/tmp/providapt-vm-fleet-6b98ce5/vm-fleet-verification.json` |
| Open-source residue | pass | `/tmp/providapt-vm-open-source-residue-6b98ce5/vm-open-source-residue.json` |
| Trace SVG stress | pass | `/tmp/providapt-trace-stress-6b98ce5/trace-svg-stress.json` |
| Browser visual baseline | pass | `/tmp/providapt-visual-regression-6b98ce5/visual-regression-snapshots.json` |
| Visual gate | pass | `/tmp/providapt-visual-regression-6b98ce5/visual-regression-gate.json` |

Dashboard browser DOM assertions passed for all required viewports:

| Viewport | Horizontal Overflow | Element Overflow | Text Overflow | View Menu Covered |
| --- | ---: | ---: | ---: | --- |
| `390x844` | 0 | 0 | 0 | no |
| `1366x768` | 0 | 0 | 0 | no |
| `1920x1080` | 0 | 0 | 0 | no |
| `2560x1080` | 0 | 0 | 0 | no |

## Notes

- The Dashboard navigation now keeps the `View` panel above the Dashboard shell
  with an explicit stacking context.
- Mobile layouts expand the `View` panel in normal document flow so it does not
  float over or under the content.
- The browser baseline keeps the menu closed in screenshots, while the DOM
  assertion temporarily opens it and verifies that it is visible and not covered.
