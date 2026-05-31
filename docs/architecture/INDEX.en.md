# System Architecture

This section describes the overall architecture design and core implementation principles of ProvidAPT.

## Documents

| Document | Description |
| --- | --- |
| [overview.md](overview.md) | System Panorama (v2.2): layered architecture, data flow, core component interaction |
| [architecture-v1.md](architecture-v1.md) | v1 Technical Architecture (production-ready baseline) |
| [provenance-model.en.md](provenance-model.en.md) | W3C PROV-compatible provenance data model and graph storage structure |
| [taint-scoring.md](taint-scoring.md) | Taint propagation model: marking rules, propagation strategies, scoring formulas |

## Core Layers

```text
UI Layer → Analysis Engine Layer → Storage Layer → Kernel eBPF Layer
```

All layers communicate via gRPC + Protobuf, and data is organized and queried as a directed acyclic graph (DAG).
