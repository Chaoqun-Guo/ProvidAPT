# VM Release Evidence - 2026-08-26

Date: 2026-08-26
Commit: `cb0235bd07b6f46c874a6d0fd61bd14840e8cb26`
Scope: three Tailscale-connected VMs using short hostnames
Status: VM evidence pass after deploying commit `cb0235b`

This record summarizes VM evidence generated from `/tmp` artifacts after the
Dashboard panel-template split. It intentionally excludes screenshots, copied
NDJSON, service logs, VM credentials, and raw event payloads.

## VM Scope

| Role | SSH Target | Result |
| --- | --- | --- |
| Ubuntu control/server | `ubuntu@vm-ubuntu-master` | PASS |
| CentOS agent | `centos@vm-centos-slave` | PASS |
| Ubuntu agent | `ubuntu@vm-ubuntu-slave` | PASS |

## Deployment

The same Linux `providaptd` binary was installed on all three VMs.

| Check | Result |
| --- | --- |
| Service state | `active` on all hosts |
| Binary SHA-256 | `e59a4f9ebda8f887c799d10dfe45e36b6891580428e5dab6c5c8e0585aecd36e` |
| Runtime version | `v1.2.2-289-gcb0235b` |

## Open Source Residue

Command:

```bash
make verify-vm-open-source-residue \
  PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave" \
  PROVIDAPT_SERVER_URL=http://vm-ubuntu-master:18080 \
  OUT_DIR=/tmp/providapt-vm-open-source-residue-cb0235b
```

Result:

| Check | Result |
| --- | --- |
| Gate status | PASS |
| Hosts checked | 3 |
| Failures | 0 |
| Dashboard/API legacy markers | none |

## Trace SVG Stress

Command:

```bash
make trace-svg-stress \
  PROVIDAPT_SERVER_URL=http://vm-ubuntu-master:18080 \
  OUT_DIR=/tmp/providapt-trace-stress-cb0235b \
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
| Latency p95 | 2080.34 ms |
| Max latency | 2455.79 ms |

Layout summary:

| Layout | Results | Pass | Node Range | Max Latency |
| --- | ---: | ---: | --- | ---: |
| tree | 3 | 3 | 12-15 | 2455.79 ms |
| compact | 3 | 3 | 16-16 | 1681.19 ms |
| timeline | 3 | 3 | 12-15 | 1773.15 ms |
| grouped | 3 | 3 | 12-15 | 1770.62 ms |

## Browser Visual Baseline

Commands:

```bash
python3 scripts/ops/visual-regression-snapshots.py \
  --server http://vm-ubuntu-master:18080 \
  --alert-id p:46583 \
  --out-dir /tmp/providapt-visual-regression-cb0235b \
  --promote-baseline /tmp/providapt-release-evidence/visual-baseline-cb0235b

python3 scripts/ops/visual-regression-gate.py \
  --manifest /tmp/providapt-visual-regression-cb0235b/visual-regression-snapshots.json \
  --out-json /tmp/providapt-visual-regression-cb0235b/visual-regression-gate.json \
  --out-md /tmp/providapt-visual-regression-cb0235b/visual-regression-gate.md
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

## Capture And Enrichment

Command:

```bash
make collect-vm-capture-evidence \
  PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave" \
  OUT_DIR=/tmp/providapt-vm-capture-evidence-cb0235b
```

Result:

| Check | Result |
| --- | --- |
| VM capture evidence | PASS |
| Hosts collected | 3 |
| Capture enrichment field gate | PASS |
| Events evaluated | 69884 |
| File events | 69871 |
| Network events | 12 |

Field coverage:

| Field | Coverage |
| --- | ---: |
| event type | 100.0% |
| PID | 100.0% |
| PPID | 99.98% |
| UID | 100.0% |
| GID | 100.0% |
| cmdline | 99.98% |
| exe path | 99.98% |
| pathname | 100.0% |
| network tuple | 100.0% |

## Residual Notes

- The VM evidence is valid for deployed build `cb0235b`.
- Raw screenshots and copied VM event files remain under `/tmp` and are not
  tracked in Git.
- A true 24-72 hour soak still requires a long-running VM collection window.
