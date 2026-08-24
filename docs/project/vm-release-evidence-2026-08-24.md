# VM Release Evidence - 2026-08-24

Date: 2026-08-24
Commit: `dcdee7c8dab055cbe701f88fd55ea4a4819ad1e3`
Scope: three Tailscale-connected VMs using short hostnames
Status: VM evidence pass after deploying commit `dcdee7c`

This record summarizes VM evidence generated from `/tmp` artifacts after the
open-source cleanup and the `dcdee7c` VM redeploy. It intentionally excludes screenshots, copied NDJSON,
service logs, VM credentials, and raw event payloads.

## VM Scope

| Role | SSH Target | Result |
| --- | --- | --- |
| Ubuntu control/server | `ubuntu@vm-ubuntu-master` | PASS |
| CentOS agent | `centos@vm-centos-slave` | PASS |
| Ubuntu agent | `ubuntu@vm-ubuntu-slave` | PASS |

## Open Source Residue

Command:

```bash
make verify-vm-open-source-residue \
  PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave" \
  PROVIDAPT_SERVER_URL=http://vm-ubuntu-master:18080 \
  OUT_DIR=/tmp/providapt-vm-open-source-residue-dcdee7c
```

Result:

| Check | Result |
| --- | --- |
| Gate status | PASS |
| Hosts checked | 3 |
| Failures | 0 |
| Dashboard HTTP | 200 |
| `control/policies` HTTP | 200 |
| `evaluation/ground-truth` HTTP | 200 |

Cleanup performed before the pass:

- Removed stale `30-api-auth.conf` and `90-api-key-rotation.conf` systemd
  drop-ins from all three VMs.
- Stopped and removed the stale `providapt-auth-server` container on
  `vm-ubuntu-master`.
- Restarted `providapt.service` on all three VMs.

## Trace SVG Stress

Command:

```bash
make trace-svg-stress \
  PROVIDAPT_SERVER_URL=http://vm-ubuntu-master:18080 \
  OUT_DIR=/tmp/providapt-trace-stress-dcdee7c \
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
| Latency p50 | 1605.95 ms |
| Latency p95 | 1864.74 ms |
| Max latency | 1899.01 ms |

Layout summary:

| Layout | Results | Pass | Node Range | Max Latency |
| --- | ---: | ---: | --- | ---: |
| tree | 3 | 3 | 9-13 | 1688.02 ms |
| compact | 3 | 3 | 9-15 | 1899.01 ms |
| timeline | 3 | 3 | 14-16 | 1597.58 ms |
| grouped | 3 | 3 | 12-15 | 1836.70 ms |

## Browser Visual Baseline

Commands:

```bash
python3 scripts/ops/visual-regression-snapshots.py \
  --server http://vm-ubuntu-master:18080 \
  --alert-id p:39474 \
  --out-dir /tmp/providapt-visual-regression-dcdee7c \
  --promote-baseline /tmp/providapt-release-evidence/visual-baseline-dcdee7c

python3 scripts/ops/visual-regression-gate.py \
  --manifest /tmp/providapt-visual-regression-dcdee7c/visual-regression-snapshots.json \
  --out-json /tmp/providapt-visual-regression-dcdee7c/visual-regression-gate.json \
  --out-md /tmp/providapt-visual-regression-dcdee7c/visual-regression-gate.md
```

Result:

| Metric | Value |
| --- | ---: |
| Gate status | PASS |
| Screenshots captured | 8 |
| Dashboard screenshots | 4 |
| Trace Viewer screenshots | 4 |
| Required matrix complete | true |
| Missing required screenshots | 0 |
| DOM assertion failures | 0 |
| DOM assertions total | 8 |

Viewport coverage:

- `390x844`
- `1366x768`
- `1920x1080`
- `2560x1080`

## Capture And Enrichment

Command:

```bash
make collect-vm-capture-evidence \
  PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave" \
  OUT_DIR=/tmp/providapt-vm-capture-evidence-dcdee7c
```

Result:

| Check | Result |
| --- | --- |
| VM capture evidence | PASS |
| Hosts collected | 3 |
| Capture enrichment field gate | PASS |
| Events evaluated | 72017 |
| File events | 72009 |
| Network events | 7 |

Field coverage:

| Field | Coverage |
| --- | ---: |
| event type | 100.0% |
| PID | 100.0% |
| PPID | 99.99% |
| UID | 100.0% |
| GID | 100.0% |
| cmdline | 99.98% |
| exe path | 99.98% |
| pathname | 100.0% |
| network tuple | 100.0% |

## Residual Notes

- The VM evidence is valid for the deployed VM build `dcdee7c`; re-run after
  deploying newer commits.
- Trace SVG stress used `MAX_LATENCY_MS=4000` to leave headroom for VM/browser
  variance while still recording the observed p95 latency.
- Raw screenshots and copied VM event files remain under `/tmp` and are not
  tracked in Git.
