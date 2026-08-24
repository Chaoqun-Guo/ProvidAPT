# Sizing Guide

This guide gives initial sizing recommendations for ProvidAPT deployments. Validate final values with representative traffic and retention requirements.

## Agent Sizing

| Workload | CPU | Memory | Local Disk | Notes |
| --- | --- | --- | --- | --- |
| Lab / demo | 1 vCPU | 512 MiB | 2 GiB | Short retention and low event rate |
| Standard server | 2 vCPU | 1-2 GiB | 10-20 GiB | Typical Linux server capture |
| Busy build host | 4 vCPU | 4 GiB | 50 GiB | High process and file churn |
| High-throughput gateway | 4-8 vCPU | 4-8 GiB | 100 GiB+ | Tune capture filters and retention |

## Control Plane Sizing

| Fleet Size | CPU | Memory | PostgreSQL | Notes |
| --- | --- | --- | --- | --- |
| 1-10 agents | 2 vCPU | 4 GiB | 2 vCPU / 4 GiB | POC and small production |
| 10-50 agents | 4 vCPU | 8 GiB | 4 vCPU / 8-16 GiB | Enable monitoring dashboards |
| 50-200 agents | 8 vCPU | 16 GiB | 8 vCPU / 32 GiB | Use dedicated PostgreSQL storage |
| 200+ agents | custom sizing | custom sizing | custom sizing | Benchmark with representative workloads |

## Storage Drivers

- Use PostgreSQL for production control-plane state.
- Use SSD-backed local storage for agent event buffers and support bundles.
- Keep raw event retention short unless required for compliance.
- Export long-term evidence to operator-controlled object storage or archival systems.

## Event Rate Controls

Use these controls to keep event volume predictable:

- `capture.include_comms` for command allow-listing.
- policy target groups for staged rollout.
- retention settings for audit, support bundles, and graph data.
- SIEM minimum severity and delivery outbox limits.

## Capacity Review Inputs

Collect these before final sizing:

- number of agents
- expected process and file churn
- target retention days
- alert volume target
- SIEM delivery rate
- PostgreSQL backup and restore objective
- support bundle size limits
