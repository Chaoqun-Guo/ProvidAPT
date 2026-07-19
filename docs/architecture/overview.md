# ProvidAPT — Architecture Whitepaper

**Version 2.2** | Provenance-based Attack Detection & Active Defense

---

## 1. System Overview

ProvidAPT is a Linux provenance monitor that uses eBPF to capture kernel-level events and reconstructs them into a W3C PROV-compliant directed acyclic graph (DAG). Designed for APT attack detection, supply chain forensics, and active defense.

### 1.1 Architecture Layers

```
┌──────────────────────────────────────────────────────────────────┐
│                      User Interface Layer                        │
│  providaptd | providaptctl | providapt-verify | HTTP API | CLI   │
├──────────────────────────────────────────────────────────────────┤
│                       Analysis Layer                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────────┐ │
│  │ Taint    │ │ Pattern  │ │ Scoring  │ │ Graph Sketch       │ │
│  │ Engine   │ │ Matcher  │ │ Engine   │ │ (Feature Vectors)  │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────────┐ │
│  │ Supply   │ │ Memory   │ │ Deception│ │ Entropy Detector   │ │
│  │ Chain    │ │ Forensic │ │ (Honeypot)│ │ (KL Divergence)   │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│                      Storage Layer                               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Pebble (RocksDB-compatible)                             │   │
│  │  Hot: LRU Cache (8K nodes) → Cold: Pebble → Archive: S3 │   │
│  └──────────────────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────────────────────┤
│                   Kernel Layer (eBPF)                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ LSM Hooks│ │ Kprobes  │ │Tracepoints│ │ Deception│          │
│  │(file_open│ │(do_unlink│ │ (sys_enter│ │ (sys_enter│          │
│  │ task_alloc│ │ )        │ │  _openat)│ │  _getdents│          │
│  │ socket   │ │          │ │ memfd)   │ │   _statx)│          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│         │            │            │              │              │
│         └────────────┴────────────┴──────────────┘              │
│                          │                                      │
│                    ┌─────▼──────┐                               │
│                    │ BPF Ringbuf │  (4 MB, 332-byte records)    │
│                    └────────────┘                               │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 Core Components

| Component | Path | Function |
|-----------|------|----------|
| **Agent (providaptd)** | `cmd/agent/daemon/` | Main daemon: loads eBPF, ingests events, builds graph |
| **Pipeline** | `internal/engine/pipeline/` | Event ingestion, dedup, backpressure |
| **Provenance Graph** | `internal/engine/provenance/` | W3C PROV DAG in memory |
| **Analyzer** | `internal/engine/analyzer/` | Taint propagation + pattern matching |
| **Central Server** | `internal/stitcher/server/` | Cross-host stitching & correlation |
| **Transport** | `pkg/transport/` | Zstd compression, hash dedup, priority queue |
| **Supply Chain** | `internal/policy/supplychain/` | SBOM import, package monitoring, risk scoring |
| **Memory Forensic** | `internal/engine/memforensic/` | Process memory dump + YARA scanning |
| **Deception** | `internal/policy/deception/` | Honeytoken injection, CGroup freeze |
| **Graph Sketch** | `internal/stitcher/graphsketch/` | Feature vectors, KL entropy detection |

### 1.3 Event Data Flow

```
eBPF Hook → Ring Buffer (4 MB shared mem) → ZeroCopyReader
  → Worker Pool (GOMAXPROCS) → MergeWindow (5s dedup)
    → Provenance Graph (DAG) → Analyzer (Taint + Patterns)
      → Alert Pipeline → Webhook / SIEM

Concurrently:
  Graph → LRU Cache → Pebble (cold storage)
  Analyzer → GraphSketch (feature vectors → upload to central)
  Analyzer → MemoryForensic (if mprotect RX detected)
  Pipeline → SupplyChain (if package manager execve)
```

---

## 2. Kernel Mechanisms

### 2.1 eBPF Hooks

ProvidAPT uses three eBPF hook types for comprehensive coverage:

| Hook Type | Programs | Coverage |
|-----------|----------|----------|
| **LSM** (BPF LSM) | `lsm_hooks.bpf.c`, `defense.bpf.c` | file_open, bprm_check, task_alloc, socket_connect, file_permission |
| **Tracepoints** | `memory.bpf.c`, `deception.bpf.c` | sys_enter_memfd_create, sys_enter_mprotect, sys_enter_openat, sys_enter_statx, sys_enter_getdents64 |
| **Kprobes** | `kprobes.bpf.c` | do_unlinkat, security_capable |

### 2.2 CO-RE Compatibility

All eBPF programs use BTF-powered CO-RE relocation via `BPF_CORE_READ()` macros. The compiled `.bpf.o` bytecode is kernel-version-independent (≥5.11).

### 2.3 Taint Tracking

Per-process taint flags propagate through the process tree:

| Flag | Bit | Set By |
|------|-----|--------|
| `TAINT_NET_CONNECT` | 0 | External IP connection |
| `TAINT_FILE_WRITE` | 1 | Sensitive path write |
| `TAINT_SETUID` | 2 | Privilege escalation |
| `TAINT_PARENT` | 3 | Inherited from parent on fork |
| `TAINT_HONEYPOT` | 4 | Honeytoken file access |

### 2.4 Adaptive Sampling

High-frequency hooks (file_permission) use adaptive sampling:
- Accumulate counts in `sample_counters` map
- Emit `EV_SAMPLE` when count ≥ 1000 OR 1 second elapsed
- Per-process detail level: `DETAIL_CORE` (minimal) → `DETAIL_FULL` (all events)

---

## 3. Provenance Model

### 3.1 W3C PROV-DM Implementation

Three node types:
- **prov:Activity** — Processes (actors)
- **prov:Entity** — Files, network, memory regions, pipes
- **prov:Agent** — Users (via PAM identity)

Six edge relations:
- `prov:used` — Activity read/connected to Entity
- `prov:wasGeneratedBy` — Entity created by Activity
- `prov:wasInformedBy` — Causality between Activities (fork, IPC)
- `prov:wasDerivedFrom` — Entity version chain
- `prov:hadSecurityContext` — Activity → Credential binding
- `prov:wasAttributedTo` — Package metadata → File attribution

### 3.2 Node ID Format

| Type | Format | Example |
|------|--------|---------|
| Process | `p:<pid>` | `p:1234` |
| File (inode) | `f:<inode>:<major>:<minor>` | `f:5000:8:3` |
| File (versioned) | `f:<inode>#v<ver>` | `f:5000:8:3#v2` |
| Network | `n:<addr>:<port>` | `n:10.0.0.5:4444` |
| Memory (mprotect) | `rx:<addr>:<pid>` | `rx:7f1234:100` |
| memfd | `memfd:<pid>:<ts>` | `memfd:400:1` |
| Pipe | `pipe:<pid>:<ts>` | `pipe:300:1` |
| Credential | `c:<pid>:<ns>` | `c:1234:1` |

### 3.3 Event-to-Graph Mapping

| Event | PROV Pattern | Subtype |
|-------|-------------|---------|
| process_fork | `wasInformedBy(child, parent)` | process→process |
| process_exec | `used(proc, binary_file)` | process→file |
| file_read | `used(proc, file)` | process→file |
| file_write | `wasGeneratedBy(file, proc)` | file→process |
| net_connect | `used(proc, network)` | process→network |
| memfd_create | `used(proc, anonymous_file)` | process→memory |
| mprotect_rx | `used(proc, memory_region)` | process→memory |
| setuid | `hadSecurityContext(proc, credential)` | process→credential |

---

## 4. Data Reduction

### 4.1 Merge Window (Sliding-Window Dedup)

Identical edges (same source, target, relation) within 5-second window are merged by incrementing `Count`. Result: 500 identical events → 1 edge with `count=500`.

### 4.2 Causality-Preserving Node Merging

Short-lived intermediate nodes (lifespan < 5 min, degree ≤ 2, no external IO) are replaced by direct edges.

### 4.3 Semantic Summary Generation

Edges older than 7 days are grouped into BehaviourSummary entries, reducing storage by ~99.9% for aged data.

---

## 5. Distributed Stitching

### 5.1 Cross-Host Stitch Table

`internal/stitcher/stitch/` — matches outbound TCP flows on host-A with inbound flows on host-B within 30-second window:

```
Host-A: SRC=10.0.0.1:45678 → DST=10.0.0.5:4444
Host-B: SRC=10.0.0.1:45678 → DST=10.0.0.5:22
  → Match via (SrcIP, DstIP, DstPort, time window)
  → StitchEdge: {remote_call | lateral_move}
```

### 5.2 Transport Layer

`pkg/transport/` — optimized for distributed scenarios:
- **Zstd dictionary compression** — trained dictionary for 112KB blocks
- **Hash cache** — SHA256 content dedup, heartbeat-only for repeats
- **Priority pipeline** — high-risk events immediate, low-risk batched hourly
- **gRPC transport** — mTLS, keepalive, 64MB max message size

---

## 6. Component Modules

### 6.1 Supply Chain Provenance (`internal/policy/supplychain/`)

- **PackageManagerMonitor** — tracks apt/yum/pip execve→file_write flows
- **SBOMStore** — imports SPDX 2.3 & CycloneDX 1.4+ JSON
- **IllegalSourceDetector** — flags curl→/usr/bin as CRITICAL risk
- **Risk scoring** — 6 weighted factors (untrusted writer +60, unsigned +50, etc.)

### 6.2 Memory Forensics (`internal/engine/memforensic/`)

- **Trigger** — mprotect RW→RX on tainted process, fileless exec, deep taint
- **Acquirer** — reads `/proc/pid/maps` + `/proc/pid/mem` for stack/exec/heap
- **Scanner** — YARA integration + 13 built-in hex patterns (Cobalt Strike, Meterpreter, shellcode)
- **Integration** — attaches `mem_risk_level`, `mem_matches` to graph nodes

### 6.3 Active Deception (`internal/policy/deception/`)

- **Overlay injection** — overlayfs mounts inject phantom sensitive files
- **eBPF monitoring** — `sys_enter_openat`/`statx`/`getdents64` path matching
- **CGroup freeze** — `cpu.max=1%` + optional `cgroup.freeze` on tripwire hit
- **Context capture** — `/proc/pid/{maps,fd,env,status}` preserved for analysis

### 6.4 Graph Sketching & Entropy (`internal/stitcher/graphsketch/`)

- **Feature vectors** — degree distribution, path depth, in/out ratio, density
- **Entropy detection** — KL divergence against EMA baseline (α=0.3)
- **Anomaly threshold** — mean + 3σ triggers force upload
- **Compressed upload** — gzip'd JSON batches (60s flush, 50/batch)

---

## 7. Threat Detection Matrix

| Detection | Module | Trigger | Severity |
|-----------|--------|---------|----------|
| Sensitive file + network | Analyzer (PatSensitiveExfil) | Taint + file/net edges | HIGH |
| Script child execution | Analyzer (PatScriptChild) | Taint + write→exec chain | CRITICAL |
| Deep taint chain (≥3 hops) | Analyzer (PatDeepTaint) | Propagation depth | MEDIUM |
| Privilege escalation | Analyzer (PatPrivEsc) | setuid attribute | HIGH |
| Memory anomaly | Analyzer (PatMemoryAnomaly) | mprotect RW→RX / fileless | CRITICAL |
| Supply chain risk | SupplyChain detector | curl→/usr/bin / unsigned pkg | CRITICAL |
| Entropy spike | GraphSketch detector | KL > mean+3σ | HIGH |
| Honeytoken trigger | Deception monitor | openat on phantom file | CRITICAL |
| C2 JA3 fingerprint | JA3 correlator | Atypical TLS handshake | HIGH |
| Cross-host lateral | Stitch engine | SSH/SCP flow match | HIGH |
| Shellcode in memory | MemForensic scanner | YARA match | CRITICAL |

---

## 8. Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| Event throughput | 50,000 evt/s | Sustained, with dedup enabled |
| Event size | 340 bytes | Fixed-size ring buffer record |
| eBPF hook latency | <1 µs | BPF-verified bounded execution |
| Graph node memory | ~512 bytes/node | In-memory DAG |
| LRU cache hit rate | ~85% | 8,192 node capacity |
| Merge reduction | ~40-99% | Depends on event repetition |
| Ring buffer | 4 MB | BPF_MAP_TYPE_RINGBUF |
| RocksDB write latency | ~400 µs per batch | 200 ops per WriteBatch |
| gRPC message max | 64 MB | mTLS encrypted transport |
