# VM Release Evidence - 2026-08-24

Date: 2026-08-24
Commit: `11fc999bbc0186940f021f56bc1ba0d30ca01050`
Scope: three Tailscale-connected VMs using short hostnames
Status: VM evidence pass after open-source residue cleanup

This record summarizes VM evidence generated from `/tmp` artifacts after the
open-source cleanup. It intentionally excludes screenshots, copied NDJSON,
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
  OUT_DIR=/tmp/providapt-vm-open-source-residue-after-clean
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
  OUT_DIR=/tmp/providapt-trace-stress-after-clean \
  TRACE_DISCOVER_LIMIT=3 \
  MIN_TRACE_NODES=1 \
  MAX_LATENCY_MS=3000
```

Result:

| Metric | Value |
| --- | ---: |
| Gate status | PASS |
| Discovered alerts | 3 |
| Expected alert/layout results | 12 |
| Completed alert/layout matrix | true |
| Failures | 0 |
| Latency p50 | 1839.96 ms |
| Latency p95 | 2750.44 ms |
| Max latency | 2994.99 ms |

Layout summary:

| Layout | Results | Pass | Node Range | Max Latency |
| --- | ---: | ---: | --- | ---: |
| tree | 3 | 3 | 5-8 | 2994.99 ms |
| compact | 3 | 3 | 4-8 | 2398.58 ms |
| timeline | 3 | 3 | 5-8 | 2083.05 ms |
| grouped | 3 | 3 | 5-8 | 2550.35 ms |

## Browser Visual Baseline

Commands:

```bash
python3 scripts/ops/visual-regression-snapshots.py \
  --server http://vm-ubuntu-master:18080 \
  --alert-id p:43795 \
  --out-dir /tmp/providapt-visual-regression-after-clean \
  --promote-baseline /tmp/providapt-release-evidence/visual-baseline-after-clean

python3 scripts/ops/visual-regression-gate.py \
  --manifest /tmp/providapt-visual-regression-after-clean/visual-regression-snapshots.json \
  --out-json /tmp/providapt-visual-regression-after-clean/visual-regression-gate.json \
  --out-md /tmp/providapt-visual-regression-after-clean/visual-regression-gate.md
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
  OUT_DIR=/tmp/providapt-vm-capture-evidence-after-clean
```

Result:

| Check | Result |
| --- | --- |
| VM capture evidence | PASS |
| Hosts collected | 3 |
| Capture enrichment field gate | PASS |
| Events evaluated | 71603 |
| File events | 71602 |
| Network events | 1 |

Field coverage:

| Field | Coverage |
| --- | ---: |
| event type | 100.0% |
| PID | 100.0% |
| PPID | 100.0% |
| UID | 100.0% |
| GID | 100.0% |
| cmdline | 100.0% |
| exe path | 100.0% |
| pathname | 100.0% |
| network tuple | 100.0% |

## Residual Notes

- The VM evidence is valid for the deployed VM build observed during the
  evidence run. Re-run after deploying newer commits.
- Trace SVG stress used `MAX_LATENCY_MS=3000` because the VM environment showed
  valid SVG responses with p95 latency near 2.75 seconds.
- Raw screenshots and copied VM event files remain under `/tmp` and are not
  tracked in Git.
