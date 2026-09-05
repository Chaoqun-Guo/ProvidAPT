# VM Continuous Evidence - 2026-09-05

Commit under validation: `83d942e`

This note summarizes the local VM evidence generated after redeploying the current open-source build to the three-VM lab. Raw NDJSON, screenshots, and host-specific outputs are intentionally kept out of this document because they can contain environment details.

## Evidence Summary

| Area | Status | Result |
| --- | --- | --- |
| VM deployment | `pass` | All three VMs reported `ProvidAPT vv1.2.3-4-g83d942e [commit 83d942e, built 2026-09-05T07:56:19Z]`. |
| Fleet health | `pass` | `3/3` agents healthy; service state `running`; dashboard fleet markers present. |
| Capture/enrichment fields | `warn` | Required field coverage passed: event type, PID, PPID, UID/GID, cmdline, exe path, pathname, and network tuple all reached `100%` in the sampled evidence. Scenario coverage did not include shell or privilege-change evidence in the final sampled window. |
| Trace SVG stress | `pass` | Four real alert IDs were tested across `tree`, `compact`, `timeline`, and `grouped` layouts; `16/16` SVG responses passed with HTTP 200 and rendered SVG content. P95 latency was about `2050 ms` under the VM lab network. |
| Browser visual baseline | `pass` | Eight real Chromium screenshots were captured for Dashboard and Trace Viewer across mobile, `1366x768`, `1920x1080`, and ultrawide viewports. DOM overflow assertions passed. |
| Support diagnostics | `pass` | Support diagnostics completed with disk/log budget evidence. |
| First-run onboarding | `blocked` | Tailscale, SSH, API, Dashboard, disk, and permissions checks passed. TLS certificate and secrets-file checks remain blocked for this lab environment until deployment-specific material is installed. |
| Daily evidence summary | `warn` | Overall daily summary remains `warn` because capture scenario coverage still lacks shell and privilege-change samples, even though required enrichment fields passed. |

## Fixes Landed During This Evidence Run

- `onboarding-wizard` now runs disk and permissions checks on the configured VM hosts when `ONBOARDING_VM_HOSTS` is supplied, instead of accidentally checking the local macOS host.
- Visual regression assertions now accept Trace Viewer's raw SVG fallback iframe as a valid rendered trace state. The report records whether the trace rendered as `inline-svg` or `fallback-iframe`.

## Evidence Output Locations

The raw artifacts were generated under local `build/` paths during validation and are intentionally not tracked by Git. Re-running the same gates will recreate evidence under equivalent paths:

| Artifact | Local path |
| --- | --- |
| Fleet verification | `build/vm-evidence-83d942e/deploy/vm-fleet-verification.json` |
| Capture/enrichment gate | `build/vm-evidence-83d942e/capture-scenarios/capture-enrichment-field-gate.json` |
| Trace SVG stress | `build/vm-evidence-83d942e/trace-stress-pass/trace-svg-stress.json` |
| Visual baseline | `build/vm-evidence-83d942e/visual-real-final/visual-regression-snapshots.json` |
| Support diagnostics | `build/vm-evidence-83d942e/support/support-diagnostics.json` |
| Daily summary | `build/vm-evidence-83d942e/daily-final/daily-summary.json` |

## Remaining Work

- Add a lower-noise capture scenario runner or sampling mode so shell, file mutation, network, process-chain, and privilege-change evidence can be collected reliably without being drowned out by high-frequency file-open events.
- Install lab or production TLS certificates and deployment secret files, then rerun Operator First-Run checks to move onboarding from `blocked` to `pass`.
- Continue optimizing Trace SVG latency. The VM lab passed a `4500 ms` budget, while a stricter `1800 ms` budget still produced latency warnings.
- Keep regenerating visual baselines after Dashboard or Trace Viewer UI changes.
