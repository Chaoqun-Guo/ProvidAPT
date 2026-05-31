# Changelog

**v2.0 → v2.1 → v2.2** | All Features, Fixes, and Breaking Changes

---

## v2.2.0 (2026-05-29)

### Major Features

#### Supply Chain Provenance Tracking
- **Package Manager Monitor** (`v2.2/supplychain/monitor.go`): Tracks apt, yum, pip, npm execve events, creates PmSessions, binds installed files to package metadata
- **SBOM Import** (`v2.2/supplychain/sbom.go`): SPDX 2.3 and CycloneDX 1.4+ JSON parser, path-to-package resolution via purl index
- **Illegal Source Detection** (`v2.2/supplychain/detector.go`): Flags untrusted writes (curl→/usr/bin), tampered packages, unsigned installs
- **Risk Scoring** (`v2.2/supplychain/risk.go`): 6-factor weighted scoring (untrusted writer +60, unsigned +50, no SBOM +30, tampered +70, untrusted repo +40, suspicious origin +35)

#### Memory Forensics
- **On-Demand Process Memory Dump** (`v2.2/memforensic/acquirer.go`): Parses `/proc/pid/maps`, reads executable/stack/heap segments via `/proc/pid/mem`
- **YARA Integration** (`v2.2/memforensic/scanner.go`): External yara binary support + 13 built-in hex patterns (Cobalt Strike, Meterpreter, shellcode, reflective loader, bind shell)
- **Trigger Conditions** (`v2.2/memforensic/trigger.go`): mprotect RW→RX, fileless exec, deep taint, supply chain risk triggers
- **Graph Integration** (`v2.2/memforensic/integrate.go`): `ApplyToStringAttrs()` attaches `mem_risk_level`, `mem_matches`, `mem_stack_hash` to nodes

#### Active Deception System
- **Honeytoken Overlay Injection** (`v2.2/deception/honeytoken.go`): overlayfs mounts inject phantom files (credentials, keys, configs) into watched directories
- **eBPF Honeytoken Monitoring** (`cmd/bpf/probes/deception.bpf.c`): `sys_enter_openat`/`statx`/`getdents64` path matching, `TAINT_HONEYPOT` flag, `EV_HONEYPOT_TRIGGER` event
- **CGroup Process Freezer** (`v2.2/deception/freeze.go`): `cpu.max=1%`, optional `cgroup.freeze`, context capture (`/proc/pid/{maps,fd,env,status}`)
- **5 Default Honeytokens**: `backup_credentials.xml`, `db_backup.sql`, SSH key, config, kubeconfig

#### Graph Sketching & Entropy Detection
- **Feature Vector Computation** (`v2.2/graphsketch/sketch.go`): Degree distribution (in/out/total), path stats (max depth, components), density, in/out ratio
- **KL Divergence Entropy Detection** (`v2.2/graphsketch/entropy.go`): EMA baseline (α=0.3), KL(P‖Q) with ε=1e-10, anomaly at mean+3σ
- **Compressed Vector Upload** (`v2.2/graphsketch/upload.go`): JSON+gzip batches, 60s flush, force-upload on anomaly

#### Analyzer Integration
- **`PatMemoryAnomaly`** pattern: Detects mprotect RW→RX, fileless exec, pipe-based fileless chains
- **`SketchIntegrator`**: Converts v1 snapshots to feature vectors, runs entropy check during each scan

### Performance

- Zstd dictionary compression for transport (trained on 112KB samples)
- Pebble-backed hash cache for subgraph dedup (heartbeat-only for repeats)
- Priority pipeline: high-risk events immediate, low-risk Pebble-staged hourly
- Consistent hash router for multi-collector deployments

### Bug Fixes

- Fixed `NewStreamPipeline` signature for transport manager integration
- Fixed priority queue in-memory fallback path
- Fixed `HandleTrigger` dead code path in memory forensics

---

## v2.1.0 (2026-04-15)

### Major Features

#### Container-Aware Monitoring
- **CGroup ID Resolution** (`v2.1/container/monitor.go`): Parses `/proc/pid/cgroup` for Docker/K8s/LXC paths
- **K8s Enrichment** (`v2.1/container/k8s.go`): Real-time K8s pod metadata attachment via cgroup IDs
- **Cross-Namespace Detection** (`v2.1/container/isolate.go`): Identifies pod-to-host and cross-pod container escapes

#### Cross-Host Stitching (Beta)
- **TCP Flow Matching** (`v2.2/stitch/stitch.go`): 5-tuple + TSval fingerprint, 30-second window
- **Taint Propagation** (`v2.2/stitch/taint_prop.go`): Cross-host taint via stitch edges
- **Central Server** (`v2.2/stitch/server.go`): In-memory stitch table with agent-query API

#### Detection Engine (v2.2)
- **Anomalous Path Detector** (`v2.2/detect/path.go`): Template-based cross-host path validation
- **Credential Correlator** (`v2.2/detect/credential.go`): LSASS access + remote login linking
- **Blast Radius Calculator** (`v2.2/detect/blast.go`): BFS from root host following lateral edges

### Performance

- gRPC streaming transport with mTLS
- 64MB max message size, 10s keepalive
- Event queue with risk-score-based prioritization

---

## v2.0.0 (2026-03-01)

### Major Features

#### Core eBPF Provenance Collection
- **LSM Hooks** (`cmd/bpf/probes/lsm_hooks.bpf.c`): task_alloc, task_free, bprm_check_security, file_open, socket_connect
- **CO-RE Compatibility**: BTF-powered relocation, kernel ≥5.11 without recompilation
- **Adaptive Sampling**: Per-process detail levels (CORE/NORMAL/FULL), aggregate sampling at 1000 events/1s
- **Event Dedup**: 100ms kernel-side window via `dedup_map`, hot-path bypass

#### Memory Attack Detection
- **memfd_create** detection via tracepoint
- **mprotect RW→RX** detection via sys_enter/sys_exit mprotect
- **Pipe data flow** tracking for curl|bash detection

#### Self-Defense
- **File Protection** (`defense.bpf.c`): LSM file_permission deny for non-agent writes
- **Agent Death Monitoring**: task_free hook emits EV_AGENT_KILLED
- **Merkle Tree Anchoring**: Periodic root hashing for tamper-evident storage

#### Provenance Graph (v1)
- W3C PROV-DM compliant DAG
- LRU cache (8,192 nodes) with Pebble cold storage
- Sliding-window edge merge (5-second dedup)
- Entity versioning for file write chains

#### Analysis Engine
- **Taint Propagation**: BFS fixpoint with per-hop decay
- **4 Detection Patterns**: PatSensitiveExfil, PatScriptChild, PatDeepTaint, PatPrivEsc
- **Alert Pipeline**: Subgraph extraction, dedup, webhook output

#### Storage
- Pebble (RocksDB-compatible) with lexicographic key design
- WriteBatch optimisation (200 ops/commit)
- Time-range scans via hex-encoded timestamps

### Performance

- 50,000 events/sec throughput
- <1µs eBPF hook latency
- ~400µs RocksDB write latency per batch
- 4MB ring buffer (BPF_MAP_TYPE_RINGBUF)

### Infrastructure

- Makefile build system (v1-ebpf, v1-userspace, v1-install)
- Docker build (Ubuntu + Rocky Linux)
- CGroup setup scripts
- Systemd service files
- Attack simulation scripts
