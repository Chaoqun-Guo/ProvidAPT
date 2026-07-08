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
