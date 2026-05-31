# CLI Reference

**providaptctl, providapt-verify, providapt-watchdog, providapt-heal, providapt-deanon**

---

## 1. providaptctl — Agent Control

Primary CLI for daemon management.

### Commands

| Command | Flag | Description |
|---------|------|-------------|
| Status | `-status` | Query daemon health and event stats |
| Stop | `-stop` | Gracefully stop the daemon |
| Restart | `-restart` | Stop then start |
| Config | `-config <path>` | Specify config file (default: `/etc/providapt/providapt.toml`) |

### Usage

```bash
# Check status
providaptctl -status
# Output: ProvidAPT: running

# Graceful stop
providaptctl -stop

# Restart
providaptctl -restart

# Custom config
providaptctl -config /opt/providapt/config.toml -status
```

## 2. providapt-verify — Data Integrity

Verifies Pebble database integrity using Merkle tree anchors.

| Flag | Description | Default |
|------|-------------|---------|
| `-data` | Data directory path | `/var/lib/providapt/store` |
| `-verbose` | Show detailed verification info | false |
| `-output` | Write report to file | "" (stdout) |

### Usage

```bash
# Quick verification
providapt-verify -data /var/lib/providapt/store

# Detailed output
providapt-verify -data /var/lib/providapt/store -verbose

# Save report
providapt-verify -data /var/lib/providapt/store -output /tmp/verify.txt
```

Exit codes:
- `0`: All checks passed
- `2`: Tampering detected (files tampered or anchors failed)

## 3. providapt-watchdog — Agent Health Monitor

Monitors the main daemon and restarts on failure. Started as a systemd companion.

```bash
# Run alongside daemon
providapt-watchdog

# Watchdog monitors:
# 1. providaptd process existence
# 2. Ring buffer activity (no events for >60s = alert)
# 3. Memory pressure (self-terminate if >90%)
```

## 4. providapt-heal — Self-Healing & Impact Assessment

Post-incident remediation and forensic analysis.

| Subcommand | Description |
|------------|-------------|
| `assess` | Analyze blast radius from a compromised node |
| `rollback` | Attempt file-level rollback from provenance |
| `block` | Generate iptables/nftables blocking rules |
| `migrate` | Migrate data store between versions |

### Usage

```bash
# Assess blast radius from process PID 1234
providapt-heal assess -pid 1234

# Generate network block rules
providapt-heal block -ip 10.0.0.5 -port 4444

# Migrate database
providapt-heal migrate -from /var/lib/providapt/store-v1 -to /var/lib/providapt/store
```

## 5. providapt-deanon — De-anonymization

Resolve anonymized node IDs to original values for forensic analysis.

| Flag | Description |
|------|-------------|
| `-node` | Node ID to resolve |
| `-file` | File with list of node IDs |
| `-json` | Output in JSON format |

### Usage

```bash
# Resolve a single node
providapt-deanon -node "p:1234"

# Batch resolve
providapt-deanon -file nodes.txt -json > resolved.json
```

## 6. Integrated Test Harness (HTTP API)

The distributed collector test harness at `cmd/collector/` exposes a REST API on port 8722:

### Stitch Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/ingest-outbound` | Register outbound TCP flow |
| POST | `/ingest-inbound` | Register inbound TCP flow |
| GET | `/stitch/by-agent?agent_id=X` | Query stitch edges by agent |
| GET | `/stitch/edges` | Total stitch edge count |
| GET | `/stitch/stats` | Stitch table statistics |

### Graph Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/graph/node` | Create a graph node |
| POST | `/graph/subgraph` | Batch insert nodes + edges |
| GET | `/graph/nodes` | List all nodes |
| GET | `/graph/query-by-host?host_id=X` | Query nodes by host |
| GET | `/graph/backtrack?node_id=X` | Trace node origin across hosts |

### Detection Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/blast/calculate` | Calculate blast radius |
| POST | `/ja3/ingest` | Ingest TLS JA3 fingerprint |
| GET | `/ja3/clusters` | List JA3 clusters |
| GET | `/ja3/alerts` | List JA3-generated alerts |

### Performance Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/queue/enqueue` | Enqueue single event |
| POST | `/queue/enqueue-batch` | Enqueue batch (performance test) |
| GET | `/queue/stats` | Queue statistics |
| GET | `/all-stats` | Combined system stats |

## 7. Makefile Targets

### Build

| Target | Description |
|--------|-------------|
| `make v1` | Full v1 build (eBPF + userspace) |
| `make v1-ebpf` | Compile eBPF programs only |
| `make v1-userspace` | Compile Go binaries only |
| `make v1-install` | Build & install to system |
| `make demo` | Build v2 (development) |

### Test

| Target | Description |
|--------|-------------|
| `make test` | Run all core unit tests |
| `make ext-test` | Run extended engine/storage/policy tests |
| `make cluster-test` | Run stitcher/cluster tests |
| `make graphsketch-test` | Graph sketch tests |
| `make deception-test` | Deception module tests |
| `make supplychain-test` | Supply chain tests |

### Operations

| Target | Description |
|--------|-------------|
| `make run` | Build & run daemon |
| `make stop` | Stop daemon |
| `make restart` | Restart daemon |
| `make cgroup` | Configure cgroup limits |
| `make attack-sim` | Run attack simulation |
| `make verify-capture` | Verify provenance capture |
