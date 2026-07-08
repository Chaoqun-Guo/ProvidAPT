# ProvidAPT System Architecture

This document describes the current production architecture of ProvidAPT for the `v1.2.2` release line.

## Layered Model

```text
Kernel eBPF Layer
  -> Event Collection and Loader Layer
  -> Provenance Graph and Analysis Layer
  -> Storage and Control-Plane Layer
  -> API, CLI, and Operator Workflows
```

## Core Components

### Kernel and Loader

- eBPF probes live under `cmd/bpf/probes/`
- loader logic lives under `internal/engine/loader/`
- compiled objects are emitted to `build/ebpf/`

### Event and Graph Pipeline

- raw event collection: `internal/engine/collector/`
- pipeline stages: `internal/engine/pipeline/`, `internal/engine/filter/`, `internal/engine/fold/`
- provenance graph: `internal/engine/provenance/`
- analysis: `internal/engine/analyzer/`, `internal/engine/taint/`, `internal/policy/`

### Storage and Export

- schema and caches: `internal/storage/schema/`, `internal/storage/cache/`
- Pebble-backed persistence: `internal/storage/pebblestore/`
- export paths: `internal/storage/export/`, `internal/storage/grpcexport/`

### Control Plane

- API and dashboard: `pkg/api/`
- notifications: `pkg/notify/`
- support bundle and ticketing: `pkg/supportbundle/`, `pkg/ticketing/`
- management services: `internal/policy/mgmt/`

## Data Flow

1. eBPF probes emit kernel events into ring-buffer-backed userspace ingestion
2. collector and pipeline stages normalize, merge, and enrich events
3. provenance graph logic builds process-file-network relationships
4. analysis and policy engines score risk, produce alerts, and record audits
5. API and CLI surfaces expose control, investigation, and export workflows

## Operational Outputs

- binaries: `build/bin/`
- eBPF objects: `build/ebpf/`
- support bundles: operator-managed export path
- release packages: GoReleaser artifacts from `.github/workflows/release.yml`
