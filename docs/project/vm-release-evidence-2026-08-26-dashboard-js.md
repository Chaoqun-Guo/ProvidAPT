# VM Release Evidence - Dashboard JS Split - 2026-08-26

Date: 2026-08-26
Commit: `24bc6f4df502d1e5675a8a3a9ff6b118d363f4a4`
Scope: three Tailscale-connected VMs using short hostnames
Status: VM evidence pass after splitting Dashboard JavaScript assets

This record summarizes the VM verification for the Dashboard JavaScript split
into API, state, UI/render helper, layout, and loader/action assets. It excludes
raw screenshots, copied NDJSON, service logs, VM credentials, and raw event
payloads.

## Deployment

The same Linux `providaptd` binary was installed on all three VMs.

| Check | Result |
| --- | --- |
| Service state | `active` on all hosts |
| Binary SHA-256 | `d7e4506565564857c565b84058a599c1cf9984586b57b45a7281fe881e728c6a` |
| Runtime version | `v1.2.2-291-g24bc6f4` |

## Dashboard Asset Split

The VM Dashboard served all split JavaScript assets without authentication.

| Asset | HTTP | Bytes |
| --- | ---: | ---: |
| `/assets/dashboard-api.js` | 200 | 9035 |
| `/assets/dashboard-state.js` | 200 | 829 |
| `/assets/dashboard-ui.js` | 200 | 14539 |
| `/assets/dashboard-layout.js` | 200 | 23181 |
| `/assets/dashboard.js` | 200 | 141003 |

## Open Source Residue

Command:

```bash
make verify-vm-open-source-residue \
  PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave" \
  PROVIDAPT_SERVER_URL=http://vm-ubuntu-master:18080 \
  OUT_DIR=/tmp/providapt-vm-open-source-residue-24bc6f4
```

Result:

| Check | Result |
| --- | --- |
| Gate status | PASS |
| Hosts checked | 3 |
| Failures | 0 |

## Trace SVG Stress

Command:

```bash
make trace-svg-stress \
  PROVIDAPT_SERVER_URL=http://vm-ubuntu-master:18080 \
  OUT_DIR=/tmp/providapt-trace-stress-24bc6f4 \
  TRACE_DISCOVER_LIMIT=3 \
  MIN_TRACE_NODES=1 \
  MAX_LATENCY_MS=4000
```

Result:

| Metric | Value |
| --- | ---: |
| Gate status | PASS |
| Discovered alerts | 3 |
| Expected alert/layout results | 12 |
| Completed alert/layout matrix | true |
| Failures | 0 |
| Latency p95 | 1701.59 ms |
| Max latency | 1712.96 ms |

Layout summary:

| Layout | Results | Pass | Node Range | Max Latency |
| --- | ---: | ---: | --- | ---: |
| tree | 3 | 3 | 14-17 | 1625.45 ms |
| compact | 3 | 3 | 12-16 | 1683.90 ms |
| timeline | 3 | 3 | 13-17 | 1685.84 ms |
| grouped | 3 | 3 | 11-14 | 1712.96 ms |

## Browser Visual Baseline

Commands:

```bash
python3 scripts/ops/visual-regression-snapshots.py \
  --server http://vm-ubuntu-master:18080 \
  --alert-id p:46583 \
  --out-dir /tmp/providapt-visual-regression-24bc6f4 \
  --promote-baseline /tmp/providapt-release-evidence/visual-baseline-24bc6f4

python3 scripts/ops/visual-regression-gate.py \
  --manifest /tmp/providapt-visual-regression-24bc6f4/visual-regression-snapshots.json \
  --out-json /tmp/providapt-visual-regression-24bc6f4/visual-regression-gate.json \
  --out-md /tmp/providapt-visual-regression-24bc6f4/visual-regression-gate.md
```

Result:

| Metric | Value |
| --- | ---: |
| Gate status | PASS |
| Screenshots captured | 8 |
| Dashboard screenshots | 4 |
| Trace Viewer screenshots | 4 |
| Required matrix complete | true |
| DOM assertion failures | 0 |

Viewport coverage:

- `390x844`
- `1366x768`
- `1920x1080`
- `2560x1080`

## Residual Notes

- The VM evidence is valid for deployed build `24bc6f4`.
- True 24-72 hour soak, real model lifecycle evidence, and real plugin
  distribution publication remain separate long-running release evidence items.
