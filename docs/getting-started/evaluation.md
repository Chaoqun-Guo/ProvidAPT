# Evaluation and POC Guide

This guide helps a customer, sales engineer, or security operator run a bounded ProvidAPT evaluation before production rollout.

## Evaluation Goals

Use the evaluation to prove four things:

1. ProvidAPT can run safely on the target Linux kernel and deployment model.
2. eBPF telemetry is captured with acceptable CPU, memory, and disk overhead.
3. Alerts, provenance investigation, support bundle export, and audit trails work end to end.
4. The operator team understands installation, rollback, and support escalation paths.

## Recommended Scope

| Area | Recommendation |
| --- | --- |
| Duration | 5-10 business days |
| Hosts | 3-10 representative Linux hosts or one Kubernetes node pool |
| Workloads | One low-risk production-like service, one batch workload, one test host |
| Data retention | 7-14 days for evaluation |
| Success owner | Customer security lead plus ProvidAPT sales/support engineer |

## Prerequisites

- Linux kernel 5.8+; 5.11+ recommended for BPF LSM.
- BTF available at `/sys/kernel/btf/vmlinux`.
- `clang`, `llvm-strip`, `libbpf`, and Go 1.25+ for source builds.
- A documented rollback plan before deploying to production-like systems.
- Approval for privileged eBPF collection and host-path access when using Kubernetes.

## Evaluation Flow

### 1. Environment Check

```bash
make verify-env
build/kernel_probe.sh
```

Capture kernel version, LSM configuration, BTF availability, libbpf version, and clang version.

### 2. Build or Install

```bash
make build-core
sudo make install-local
```

For packaged evaluations, record the package name, checksum, and installation log.

### 3. Start and Baseline

```bash
sudo providaptd -config /etc/providapt/providapt.toml
providaptctl -status
```

Measure agent CPU, memory, event throughput, dropped events, disk growth, and alert volume.

### 4. Validate Security Workflows

Run a safe test scenario approved by the customer:

- process execution and file access capture
- suspicious file write
- network connection event
- alert review
- provenance graph query
- support bundle export
- audit log review

### 5. Validate Operations

Confirm daemon restart behavior, support bundle redaction, backup and restore, upgrade preflight, rollback instructions, logs, and metrics.

## POC Success Criteria

| Category | Success Criteria |
| --- | --- |
| Compatibility | Target kernels and deployment model pass environment checks |
| Stability | Agent runs through the evaluation without crashes or unsafe failure modes |
| Performance | CPU, memory, disk, and dropped-event rates stay within customer-agreed limits |
| Detection | Approved test scenarios produce explainable alerts and provenance context |
| Operations | Support bundle, audit log, upgrade preflight, and rollback procedures are understood |
| Handoff | Customer receives findings, limitations, sizing notes, and next-step plan |

## Evidence to Save

- `providaptctl -status` output
- kernel probe output
- build or package installation logs
- metrics snapshot before and after the test scenario
- alert IDs and related provenance query output
- support bundle export confirmation
- upgrade preflight output
- known limitations and agreed waivers

## Exit Report Template

```text
Customer:
Environment:
Evaluation dates:
Hosts / nodes:
Workloads:
Version:
Result: pass / pass with conditions / fail

Findings:
- Compatibility:
- Performance:
- Detection:
- Operations:
- Limitations:

Recommended next step:
```
## Detector Training Dataset Export

ProvidAPT can export safe attack-simulation ground truth into deterministic
training and test datasets. Use this flow after running `attack-full-chain` on
one or more validation hosts.

## Export Dataset

```bash
make export-ground-truth \
  GROUND_TRUTH=/var/log/providapt/ground-truth \
  OUT_DIR=build/evaluation-dataset
```

Outputs:

| File | Purpose |
| --- | --- |
| `labels.jsonl` | normalized labels for all ground-truth records |
| `train.jsonl` | deterministic training split |
| `test.jsonl` | deterministic test split |
| `coverage.json` | machine-readable ATT&CK coverage summary |
| `coverage.md` | analyst-readable coverage report |
| `manifest.json` | dataset ID, optional version label, split seed, ratio, split summary, and hashed output inventory |

`manifest.json` includes a deterministic `dataset_id` derived from normalized
labels plus split settings. Use it as the immutable training input identifier
when comparing detector versions. Each output file also includes byte size and
SHA-256 so training jobs can verify that labels were not modified after export.

## Merge Detection Correlation

Export correlation from the control plane:

```bash
curl -s http://<server>:18080/api/v1/evaluation/correlation?limit=1000 \
  -o build/evaluation-correlation.json
```

Then merge it into the coverage report:

```bash
make export-ground-truth \
  GROUND_TRUTH=/var/log/providapt/ground-truth \
  OUT_DIR=build/evaluation-dataset \
  CORRELATION_JSON=build/evaluation-correlation.json
```

When correlation is supplied, `coverage.json` reports detected and missed
records by run, tactic, and technique. Without correlation, it reports simulated
coverage only.

## Dataset Rules

- Keep ground-truth JSONL and manifests with the captured NDJSON logs.
- Do not mix clean-room simulation data with ad-hoc manual testing in the same
  dataset export.
- Preserve `run_id`, `step_id`, `tactic_id`, `technique_id`, `expected_event`,
  `actor`, and `object`; these fields are the minimum viable training label.
- Use a fixed `--seed` and `--train-ratio` for repeatable model comparisons.
- Record model training inputs by commit, host, kernel mode, and simulation run.

## Alert Quality Feedback

After analysts mark alerts as `true_positive`, `false_positive`, `benign`, or
`duplicate`, export review metrics:

```bash
make alert-quality ALERTS=/var/log/providapt OUT_DIR=build/evaluation
```

Use `alert-quality.json` as machine-readable detector quality evidence and
`alert-quality.md` for rule review meetings.

The dashboard Alert Workflow panel also computes the same release-facing review
coverage, precision, duplicate, and needs-review counters from currently loaded
alerts. Use the `Quality` action for analyst triage and `Export Quality` to
download a JSON snapshot from the browser.

## Model Registry and Drift

Register a trained detector against the exact dataset manifest used for
training:

```bash
make model-feature-schema OUT_DIR=build/evaluation

make model-register \
  DATASET_MANIFEST=build/evaluation-dataset/manifest.json \
  MODEL_NAME=providapt-detector \
  MODEL_VERSION=1.0.0 \
  MODEL_METRICS=build/evaluation/alert-quality.json \
  FEATURE_SCHEMA=build/evaluation/model-feature-schema.json \
  COMMIT="$(git rev-parse --short HEAD)"
```

The registry stores the dataset ID, optional dataset version, manifest SHA-256,
metrics SHA-256, model feature schema hash, model name, model version, commit,
and registration time.

Validate a candidate feature schema before registering or deploying a model:

```bash
make model-feature-schema-check \
  FEATURE_SCHEMA=build/evaluation/model-feature-schema.json \
  OUT_DIR=build/evaluation
```

The check enforces the production feature vector order and length. This prevents
a model trained on one vector layout from being used against another runtime
layout.

Compare a candidate dataset with the previous training manifest before training
or release:

```bash
make model-drift \
  BASELINE_MANIFEST=release-baseline/manifest.json \
  CANDIDATE_MANIFEST=build/evaluation-dataset/manifest.json \
  OUT_DIR=build/evaluation
```

`model-drift.json` is machine-readable release evidence. `model-drift.md`
summarizes changes by split, tactic, and technique and marks fields that exceed
the configured drift threshold.

## Detection Quality Gate

Merge ATT&CK coverage and analyst alert quality into one precision/recall/F1
gate:

```bash
make detection-quality \
  COVERAGE_JSON=build/evaluation-dataset/coverage.json \
  ALERT_QUALITY_JSON=build/evaluation/alert-quality.json \
  OUT_DIR=build/evaluation
```

`detection-quality.json` is the P2 release evidence artifact for recall,
precision, F1, missed tactics, missed techniques, and rule-tuning
recommendations.

## Model Deployment Gate

Before enabling a trained detector in production, gate the model against the
registry, feature schema, quality metrics, and dataset drift evidence:

```bash
make model-deploy-gate \
  MODEL_REGISTRY=build/model-registry.json \
  MODEL_NAME=providapt-detector \
  MODEL_VERSION=1.0.0 \
  DETECTION_QUALITY_JSON=build/evaluation/detection-quality.json \
  MODEL_DRIFT_JSON=build/evaluation/model-drift.json \
  FEATURE_SCHEMA_CHECK_JSON=build/evaluation/model-feature-schema-check.json \
  OUT_DIR=build/evaluation
```

The gate blocks deployment when:

- The model is missing from the registry.
- The registered feature schema hash or vector length is absent.
- Precision or recall is below the configured threshold.
- Drift status is `review_required`.
- Feature schema validation did not pass.

Tune thresholds when needed:

```bash
make model-deploy-gate \
  MODEL_REGISTRY=build/model-registry.json \
  MODEL_NAME=providapt-detector \
  MODEL_VERSION=1.0.0 \
  MIN_PRECISION=75 \
  MIN_RECALL=85
```

Outputs:

| File | Purpose |
| --- | --- |
| `model-deploy-gate.json` | Machine-readable deployment decision and evidence summary |
| `model-deploy-gate.md` | Operator-readable approval checklist |

Keep the gate output with the model artifact, dataset manifest, drift report,
feature schema report, and release evidence bundle.

## P2 ML Readiness Gate

Before marking P2 complete, run the dataset-quality and model-quality readiness
gate against the exact VM-captured dataset and trained model metrics:

```bash
make p2-readiness \
  DATASET_MANIFEST=build/ml-dataset/manifest.json \
  MODEL_METRICS=build/ml-model/metrics.json \
  MODEL_GATE=build/evaluation/model-deploy-gate.json \
  EVENTS=build/vm-training/attack_events.ndjson \
  NORMAL_EVENTS=build/vm-training/normal.ndjson \
  GROUND_TRUTH=build/vm-training/ground_truth.jsonl \
  OUT_DIR=build/p2
```

The gate verifies:

- graph count, source event count, benign graph count, and malicious graph count
- ground-truth match rate between simulated ATT&CK steps and captured events
- command-line, path, and enrichment-field presence in the source events
- precision, recall, F1, ROC AUC, PR AUC, test support, and confusion matrix
- optional deployment-gate status when `MODEL_GATE` is supplied

Use stricter thresholds for release candidates and lower thresholds only for
local smoke checks:

```bash
make p2-readiness \
  DATASET_MANIFEST=build/ml-dataset/manifest.json \
  MODEL_METRICS=build/ml-model/metrics.json \
  MIN_GRAPHS=100000 \
  MIN_SOURCE_EVENTS=1000000 \
  MIN_MALICIOUS_GRAPHS=500 \
  MIN_BENIGN_GRAPHS=50000 \
  MIN_TRUTH_MATCH_RATE=90 \
  MIN_PRECISION=80 \
  MIN_RECALL=85 \
  MIN_F1=80
```

Outputs:

| File | Purpose |
| --- | --- |
| `p2-readiness.json` | Machine-readable P2 release gate summary |
| `p2-readiness.md` | Operator-readable readiness evidence |

If the report is blocked by low truth-match or missing enrichment, fix capture
and enrichment first, recollect the VM dataset, and retrain before approving the
model. `EVENTS`, `NORMAL_EVENTS`, and `GROUND_TRUTH` are optional when the
dataset manifest already contains a `quality` section; supply them for legacy
manifests or independent capture-quality audits.

Generate a concrete backlog for missed ATT&CK techniques:

```bash
make attack-coverage-plan \
  DETECTION_QUALITY_JSON=build/evaluation/detection-quality.json \
  OUT_DIR=build/evaluation
```

The plan translates missed techniques into safe simulation guidance, expected
ground-truth fields, rule assertions, and cleanup requirements.
