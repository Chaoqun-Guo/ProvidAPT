# ProvidAPT User Manual

**Version 1.0** | Operator's Guide to Provenance Monitoring and APT Detection

This manual covers day-to-day operation of ProvidAPT, including querying the provenance graph, configuring detection policies, interpreting alerts, and performance tuning.

---

## Table of Contents

- [1. Command Line Tools](#1-command-line-tools)
- [2. ProvQL Query Guide](#2-provql-query-guide)
- [3. Policy Configuration](#3-policy-configuration)
- [4. Visualization and Reporting](#4-visualization-and-reporting)
- [5. Performance Tuning](#5-performance-tuning)
- [6. Uninstallation and Cleanup](#6-uninstallation-and-cleanup)

---

## 1. Command Line Tools

ProvidAPT ships with six command-line tools.

### 1.1 providaptctl — Control and Management

The primary administration tool for managing the ProvidAPT daemon.

```bash
# Check daemon status
providaptctl -status

# Stop the daemon
providaptctl -stop

# Restart the daemon
providaptctl -restart

# Specify configuration file
providaptctl -config /etc/providapt/providapt.toml
```

### 1.2 providaptd — Main Daemon

The provenance monitoring daemon. Typically run as a systemd service.

```bash
# Start with default configuration
sudo providaptd

# Start with custom configuration
sudo providaptd -config /etc/providapt/custom.toml

# Enable verbose logging
sudo providaptd -v

# Daemon log output: /var/log/providapt/daemon.log
```

### 1.3 providapt-watchdog — High-Availability Monitor

Monitors the main daemon and restarts it if it crashes.

```bash
# Start watchdog with default paths
sudo providapt-watchdog &

# Specify custom agent path
sudo providapt-watchdog -agent /usr/local/sbin/providaptd \
    -interval 10s
```

### 1.4 providapt-verify — Data Integrity Verifier

Scans provenance data and verifies Merkle tree hash chain integrity.

```bash
# Verify all stored data
sudo providapt-verify -data /var/lib/providapt/store

# Save report to file
sudo providapt-verify -data /var/lib/providapt/store \
    -output /tmp/integrity_report.txt

# Verbose mode (shows all errors)
sudo providapt-verify -data /var/lib/providapt/store -verbose
```

Exit codes:
- `0` — All data intact
- `2` — Tampering detected

### 1.5 providapt-deanon — Authorized De-anonymization

Recovers original sensitive values from anonymized hashes.

```bash
# Decrypt a single hash
providapt-deanon \
    -hash a3f8b2c1e4d5f6a7 \
    -key /etc/providapt/deanon.key

# Output:
# Hash:     a3f8b2c1e4d5f6a7
# Original: /etc/shadow

# List all de-anonymizable entries
providapt-deanon -list -key /etc/providapt/deanon.key
```

### 1.6 providapt-heal — Automated Incident Response

Assess attack impact, roll back changes, and block C2 communication.

```bash
# Assess impact from a malicious process (read-only)
providapt-heal -pid 1234

# Full response: kill processes + quarantine files
providapt-heal -pid 1234 -rollback -dry-run=false

# Block C2 IPs via iptables/nftables
providapt-heal -pid 1234 -firewall

# Save impact report
providapt-heal -pid 1234 -output /tmp/impact_report.json
```

---

## 2. ProvQL Query Guide

ProvQL (Provenance Query Language) is a declarative graph query language inspired by Neo4j Cypher. It enables analysts to search the provenance graph for attack patterns.

### 2.1 Syntax Reference

```sql
MATCH (variable:Label)-[:RELATION]->(variable:Label)
WHERE condition
DURING [start_time, end_time]
RETURN variable.field, variable.field
```

**Node Labels:**

| Label | Matches | Example |
|-------|---------|---------|
| `Process` | Process nodes (subtype=process) | `(p:Process)` |
| `File` | File nodes | `(f:File)` |
| `Network` | Network endpoints | `(n:Network)` |
| `Pipe` | Pipe IPC nodes | `(x:Pipe)` |
| `Memory` | Memory regions | `(m:Memory)` |

**Edge Relations:**

| Relation | PROV Mapping | Direction |
|----------|-------------|-----------|
| `WROTE` | `wasGeneratedBy` | Process → File |
| `READ` | `used` | Process → File/Network |
| `FORKED` | `wasInformedBy` | Child → Parent |
| `CONNECTED` | `used` | Process → Network |
| `DERIVED` | `wasDerivedFrom` | New File → Old File |

**WHERE Operators:**

| Operator | Description | Example |
|----------|-------------|---------|
| `=` | Exact match | `p.comm = 'bash'` |
| `STARTSWITH` | Prefix match | `f.path STARTSWITH '/etc'` |
| `CONTAINS` | Substring match | `p.comm CONTAINS 'bash'` |

**DURING Clause:**

Specifies a time window for the query:

```sql
DURING [2025-01-01T00:00:00Z, 2025-01-02T00:00:00Z]
```

### 2.2 Scenario 1: Detect Privilege Escalation

**Goal:** Find all processes that executed with setuid and then read sensitive files.

**Query:**
```sql
MATCH (p:Process)-[:READ]->(f:File)
WHERE f.path = '/etc/shadow'
  AND p.comm CONTAINS 'sudo'
RETURN p.pid, p.comm, f.path
```

**Expected result:**
```
p.pid | p.comm | f.path
1234  | sudo   | /etc/shadow
```

**Interpretation:** A process ran `sudo` and then read `/etc/shadow`. This indicates a privilege escalation attempt followed by credential access (MITRE T1548 + T1003).

### 2.3 Scenario 2: Detect Lateral Movement

**Goal:** Identify SSH-based lateral movement by finding outbound SSH connections and correlating with process spawns on the target.

**Query:**
```sql
MATCH (p:Process)-[:CONNECTED]->(n:Network)
WHERE n.label CONTAINS ':22'
  AND p.comm = 'ssh'
RETURN p.pid, p.comm, n.label
```

**Expected result:**
```
p.pid | p.comm | n.label
5678  | ssh    | 10.0.0.2:22
```

**Detection:** An SSH client process connected to a remote host. Combined with process creation events on the target, this indicates lateral movement (MITRE T1021).

### 2.4 Scenario 3: Detect Fileless Malware Execution

**Goal:** Find evidence of "living off the land" attacks where a network tool downloads and executes a script via pipe.

**Query:**
```sql
MATCH (a:Process)-[:WROTE]->(f:File)-[:READ]->(b:Process)
WHERE f.path STARTSWITH '/tmp'
  AND a.comm CONTAINS 'curl'
  AND b.comm = 'bash'
RETURN a.comm, f.path, b.comm
```

**Expected result:**
```
a.comm | f.path        | b.comm
curl   | /tmp/evil.sh  | bash
```

**Attack chain:** `curl → downloads /tmp/evil.sh → bash executes it` — classic fileless execution (MITRE T1204, T1059).

### 2.5 Scenario 4: Detect Sensitive Data Exfiltration

**Goal:** Identify processes that read sensitive files and then make network connections — the exfiltration pattern.

**Query:**
```sql
MATCH (p:Process)-[:READ]->(f:File)
WHERE f.path STARTSWITH '/etc'
RETURN p.pid, p.comm, f.path
```

Then manually verify network events for the same PID.

**Combined detection:** The analyzer engine automatically correlates `EV_FILE_OPEN` + `EV_NET_CONNECT` as `SENSITIVE_EXFIL` alerts.

### 2.6 Scenario 5: Reconstruct Full Attack Chain

**Goal:** Trace the complete provenance path from initial access to data exfiltration.

**Query:**
```sql
MATCH (a:Process)-[:FORKED]->(b:Process)-[:WROTE]->(f:File)-[:READ]->(c:Process)-[:CONNECTED]->(n:Network)
RETURN a.comm, b.comm, f.path, c.comm, n.label
```

**Expected result:**
```
a.comm  | b.comm | f.path         | c.comm | n.label
nginx   | bash   | /tmp/backdoor  | curl   | 5.6.7.8:443
```

**Full attack path:** `nginx (compromised) → bash (shell) → /tmp/backdoor (malware) → curl (C2 connection to 5.6.7.8:443)`

### 2.7 Programmatic Usage

Queries can also be executed programmatically via the HTTP API:

```bash
# Execute a ProvQL query via the API
curl -s "http://localhost:8080/api/v1/graph/export?pid=1234"

# Or use the Go library directly:
#   executor := query.NewExecutor(graph)
#   result, err := executor.Execute("MATCH ... RETURN ...")
```

---

## 3. Policy Configuration

### 3.1 Active Defense Rules

ProvidAPT supports YAML-based policy rules for active defense. Rules are loaded from `/etc/providapt/rules.yaml`.

**Example rules file:**

```yaml
# /etc/providapt/rules.yaml
version: "1.0"

# ─── Whitelist ───────────────────────────────────────────
# Processes and paths to exclude from monitoring.
# These reduce noise during normal operations.

whitelist:
  pids:
    - 1        # systemd — always active
    - 2        # kthreadd — kernel thread
  comms:
    - "yum"
    - "dnf"
    - "apt"
    - "dpkg"
    - "rpm"
    - "make"
    - "gcc"
    - "updatedb"
  paths:
    - "/usr/share/*"
    - "/usr/lib/*"
    - "/var/cache/*"

# ─── Blacklist ───────────────────────────────────────────
# Behavior that should always trigger full monitoring.

blacklist:
  sensitive_files:
    - "/etc/shadow"
    - "/etc/passwd"
    - "/etc/sudoers"
    - "/root/.ssh/*"
    - "/var/log/auth.log"

  untrusted_dirs:
    - "/tmp/*"
    - "/dev/shm/*"
    - "/var/tmp/*"

  dangerous_comms:
    - "nc"
    - "ncat"
    - "tftp"
    - "socat"

# ─── Reputation Overrides ───────────────────────────────
# Customize path reputation scores.

reputation:
  overrides:
    - pattern: "/opt/myapp/*"
      score: 90      # trusted application
    - pattern: "/home/developer/*"
      score: 70      # slightly restricted
    - pattern: "/run/user/*"
      score: 20      # suspicious

# ─── Response Actions ───────────────────────────────────
# Automated actions when certain patterns are detected.

response:
  on_sensitive_read:
    - action: "upgrade"
      level: "INVESTIGATING"

  on_network_connect:
    - action: "alert"
      severity: "HIGH"

  on_memory_injection:
    - action: "dump"
    - action: "alert"
      severity: "CRITICAL"
```

### 3.2 Adaptive Monitoring Policy

The adaptive controller uses three levels based on risk:

| Level | Name | Trigger | Capabilities |
|-------|------|---------|-------------|
| 1 | DEFAULT | Baseline | exec, fork, connect |
| 2 | SUSPICIOUS | Score ≥ 5 | +file_detail, +socket_flow, +env_capture |
| 3 | INVESTIGATING | Score ≥ 20 or repeated alerts | +syscall_trace, +memory_trace, +memory_dump |

Policy can be adjusted at runtime:

```bash
# Whitelist a process (exclude from monitoring)
# This is done automatically when the process comm matches rules.yaml
```

### 3.3 Sigma Rules

Sigma rules are built-in for common attack patterns:

```yaml
# Built-in rules (loaded automatically):
#   rule-shadow-001: Suspicious Shadow File Access
#   rule-webshell-001: Web Server Shell Spawn
#   rule-net-001: Suspicious Network Connection
#   rule-exfil-001: Sensitive File Exfiltration
#   rule-cron-001: Cron Persistence via Backdoor
#   rule-setuid-001: Privilege Escalation via setuid
```

Custom Sigma rules can be added to `/etc/providapt/sigma/`.

---

## 4. Visualization and Reporting

### 4.1 Graph Export Formats

ProvidAPT supports two export formats for the provenance graph.

#### PROV-JSON (default)

```bash
# The graph is automatically saved on shutdown:
# /var/log/providapt/provenance.json

# Manual trigger via API:
curl -s "http://localhost:8080/api/v1/graph/export?pid=1234"
```

Export structure:

```json
{
  "prefix": { "prov": "http://www.w3.org/ns/prov#" },
  "activity": {
    "p:100": { "prov:type": "prov:Activity", "prov:label": "bash", "pid": 100 }
  },
  "entity": {
    "f:5000:8:3": { "prov:type": "prov:Entity", "prov:label": "/etc/shadow" }
  },
  "used": [
    { "prov:activity": "p:100", "prov:entity": "f:5000:8:3", "prov:time": "2025-01-01T12:00:00Z" }
  ],
  "wasGeneratedBy": [],
  "wasInformedBy": []
}
```

#### GraphML (for yEd / Gephi / Cytoscape)

```bash
# Automatically saved on shutdown:
# /var/log/providapt/provenance.graphml

# Can be imported directly into:
# - yEd Graph Editor
# - Gephi
# - Cytoscape.js
```

#### Cytoscape.js JSON (for web frontends)

```bash
# All API endpoints return Cytoscape-compatible JSON:
curl -s "http://localhost:8080/api/v1/graph/export" | jq '.elements[]'
```

### 4.2 SVG Attack Path Snapshots

When an alert triggers, an SVG attack path diagram is generated.

```bash
# Retrieve the SVG for an alert
curl -s "http://localhost:8080/api/v1/alerts/INC-APT-WEB-SHELL-12345/svg" \
    -o /tmp/attack_path.svg
```

The SVG visually represents:

```
┌──────────────────────────────────────────────────────┐
│  ProvidAPT — Attack Path                              │
│                                                       │
│  ┌──────────┐    ┌──────────┐    ┌────────────────┐  │
│  │  nginx   │───▶│   bash   │───▶│  /etc/shadow   │  │
│  │ (process)│    │ (process)│    │   (file)        │  │
│  └──────────┘    └──────────┘    └────────────────┘  │
│       │              │                                 │
│       │              │  forked                          │
│       │              ▼                                 │
│       │         ┌──────────┐    ┌────────────────┐  │
│       │         │   curl   │───▶│  5.6.7.8:443   │  │
│       │         │ (process)│    │  (network)      │  │
│       │         └──────────┘    └────────────────┘  │
│       │              │                                 │
│       └──────────────┘                                 │
└──────────────────────────────────────────────────────┘
```

Node color coding:
- **Blue** `#4A90D9` — Process
- **Green** `#50B86C` — File
- **Red** `#E24C4C` — Network
- **Orange** `#E8A838` — Credential

### 4.3 AI-Generated Attack Reports

When connected to an LLM (Ollama or OpenAI), ProvidAPT can generate natural-language attack analysis reports.

```bash
# Configure LLM connection in /etc/providapt/providapt.toml:
# {
#   "ai": {
#     "provider": "ollama",
#     "endpoint": "http://localhost:11434/api/chat",
#     "model": "llama3"
#   }
# }
```

The AI report includes:

```
### Attack Path Description

The attack began with a compromise of the Nginx web server (PID 100),
which spawned a bash shell (PID 101). The attacker used this shell to:

1. Read /etc/shadow (credential access — T1003)
2. Write /tmp/backdoor.sh (defense evasion — T1204)
3. Connect to C2 server 5.6.7.8:443 (command & control — T1043)

### Affected Assets

- Processes: nginx(100), bash(101), curl(102)
- Files: /etc/shadow, /tmp/backdoor.sh
- Network: 5.6.7.8:443

### Remediation Recommendations

1. Immediately terminate PID 101 and 102
2. Quarantine /tmp/backdoor.sh for forensic analysis
3. Rotate all credentials exposed on the compromised host
4. Block 5.6.7.8 at the network perimeter

### MITRE ATT&CK Mapping

| Technique ID | Name | Phase |
|-------------|------|-------|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1059 | Command and Scripting Interpreter | Execution |
| T1003 | OS Credential Dumping | Credential Access |
| T1043 | Commonly Used Port | Command and Control |
```

### 4.4 Interactive Q&A

Analysts can ask questions about the provenance graph:

```go
// Allow questions like:
// "How did this process connect to the network?"
// "What files did bash modify?"
// "Who forked this process?"

qa := NewQAEngine(graph, llmConfig)
answer, _ := qa.Answer("What files did the attacker modify?")
// → "The attacker modified /etc/shadow (read) and /tmp/evil.sh (write)"
```

### 4.5 Performance Dashboards

ProvidAPT exposes metrics via the API:

```bash
# Get agent statistics
curl -s http://localhost:8080/api/v1/status

# Response:
# {
#   "status": "running",
#   "nodes": 15234,
#   "edges": 89201,
#   "timestamp": "2026-05-28T12:00:00Z"
# }
```

---

## 5. Performance Tuning

### 5.1 LRU Cache Size

The LRU cache holds hot (active) process nodes in memory. Adjust based on available RAM.

```go
// File: internal/engine/pipeline/pipeline.go
cfg.MaxCacheSize = 8192   // Default: 8192
// Increase to 16384 for systems with > 8 GB RAM
// Decrease to 2048 for memory-constrained systems
```

**Memory impact:**

| Cache Size | Estimated Memory | Use Case |
|-----------|-----------------|----------|
| 2,048 | ~50 MB | Low-memory / container |
| 8,192 | ~200 MB | Default |
| 32,768 | ~800 MB | High-throughput server |

### 5.2 RocksDB Compaction

Tune RocksDB for your storage hardware.

```go
// File: pkg/hwaccel/nvme.go — RocksDBConfig()

// For NVMe SSDs (default):
cfg["block_size"] = 64 * 1024                    // 64KB
cfg["max_background_compactions"] = 8            // 8 threads
cfg["use_direct_reads"] = true                   // bypass page cache

// For SATA SSDs:
cfg["block_size"] = 32 * 1024                    // 32KB
cfg["max_background_compactions"] = 4            // 4 threads
cfg["use_direct_reads"] = false

// For HDDs:
cfg["block_size"] = 16 * 1024                    // 16KB
cfg["max_background_compactions"] = 2            // 2 threads
cfg["bytes_per_sync"] = 512 * 1024               // 512KB
```

### 5.3 eBPF Sampling Rate

Adaptive sampling in the eBPF programs reduces overhead for high-frequency events.

```c
// File: cmd/bpf/headers/taint.h

// Sampling threshold: report after N occurrences
#define SAMPLE_THRESHOLD      1000U

// Or at minimum interval
#define SAMPLE_INTERVAL_NS    1000000000ULL   // 1 second
```

Adjust these for your workload:

| Threshold | Event Reduction | CPU Impact | Detection Latency |
|-----------|----------------|------------|-------------------|
| 100 | 90% | 0.5% | <100ms |
| 1,000 | 99% | 0.1% | <1s |
| 10,000 | 99.9% | 0.02% | <10s |

### 5.4 Merge Window

The sliding-window merge deduplicates repeated edges, reducing storage.

```go
// File: internal/engine/pipeline/pipeline.go
cfg.MergeWindow = 5 * time.Second   // Default

// Increase for higher compression, lower accuracy:
cfg.MergeWindow = 30 * time.Second

// Decrease for real-time accuracy, higher storage:
cfg.MergeWindow = 1 * time.Second
```

### 5.5 Batch Writer

Tune the RocksDB WriteBatch for your IOPS budget.

```go
// File: internal/engine/pipeline/batchwriter.go

// High-throughput mode (default):
// - BatchSize: 500
// - FlushInterval: 2s
// - DisableWAL: true

// Maximum durability mode:
// - BatchSize: 200
// - FlushInterval: 5s
// - DisableWAL: false
// - SyncWrites: true
```

### 5.6 Adaptive Monitoring

The adaptive controller automatically downgrades processes after a cooldown period, conserving resources.

| Level | Cooldown | Action |
|-------|----------|--------|
| SUSPICIOUS → DEFAULT | 10 min idle | Auto-downgrade |
| INVESTIGATING → DEFAULT | 5 min idle | Auto-downgrade |

To manually adjust:

```bash
# View active monitoring levels
# Check logs for: [adaptive] UPGRADE / DOWNGRADE entries
grep "\[adaptive\]" /var/log/providapt/daemon.log
```

### 5.7 Benchmarking

```bash
# Run performance benchmarks
go test -bench=BenchmarkPipelineThroughput -benchtime=30s ./test/benchmark/

# Run stress test
go run test/kernel-test/stress_test.go
```

---

## 6. Uninstallation and Cleanup

### 6.1 Safe Service Shutdown

```bash
# 1. Stop the daemon gracefully
sudo providaptctl -stop
# or
sudo systemctl stop providapt

# 2. Stop the watchdog
sudo pkill providapt-watchdog 2>/dev/null || true

# 3. Verify all processes are stopped
pidof providaptd || echo "Stopped"
```

### 6.2 Remove Binaries

```bash
# Using make uninstall
sudo make uninstall

# This removes:
#   /usr/local/sbin/providaptd
#   /usr/local/sbin/providapt-watchdog
#   /usr/local/bin/providaptctl
#   /usr/local/lib/providapt/ebpf/*.bpf.o
```

### 6.3 Unload eBPF Programs

```bash
# List all ProvidAPT eBPF programs
sudo bpftool prog list | grep -i providapt

# Detach and unload each program
# Programs are automatically unloaded when the agent process exits,
# but you can force cleanup:

# Remove pinned BPF objects
sudo rm -rf /sys/fs/bpf/providapt 2>/dev/null || true

# Reset BPF LSM
echo "" | sudo tee /sys/kernel/security/lsm 2>/dev/null || true

# Verify cleanup
sudo bpftool prog list | grep -i providapt || echo "All BPF programs cleaned"
```

### 6.4 Remove Data and Configuration

```bash
# Remove provenance data
sudo rm -rf /var/log/providapt/
sudo rm -rf /var/lib/providapt/
sudo rm -rf /etc/providapt/

# Remove cgroup limits
sudo bash build/setup_cgroup.sh --remove
```

### 6.5 Remove SystemD Service

```bash
# Disable and remove the service
sudo systemctl disable providapt.service
sudo rm /etc/systemd/system/providapt.service
sudo systemctl daemon-reload
```

### 6.6 Complete Cleanup Script

```bash
#!/bin/bash
# providapt-cleanup.sh — Complete ProvidAPT uninstallation

set -euo pipefail

echo "ProvidAPT Cleanup"
echo "================="

# Step 1: Stop services
echo "[1/6] Stopping services..."
sudo systemctl stop providapt 2>/dev/null || true
sudo pkill providaptd 2>/dev/null || true
sudo pkill providapt-watchdog 2>/dev/null || true
sleep 2

# Step 2: Unload eBPF
echo "[2/6] Unloading eBPF programs..."
sudo rm -rf /sys/fs/bpf/providapt 2>/dev/null || true

# Step 3: Remove binaries
echo "[3/6] Removing binaries..."
sudo make uninstall 2>/dev/null || true
sudo rm -f /usr/local/sbin/providapt*
sudo rm -f /usr/local/bin/providaptctl

# Step 4: Remove data
echo "[4/6] Removing data..."
sudo rm -rf /var/log/providapt/
sudo rm -rf /var/lib/providapt/
sudo rm -rf /etc/providapt/

# Step 5: Remove cgroup
echo "[5/6] Removing cgroup limits..."
sudo rmdir /sys/fs/cgroup/providapt 2>/dev/null || true

# Step 6: Remove systemd service
echo "[6/6] Removing systemd service..."
sudo rm -f /etc/systemd/system/providapt.service
sudo systemctl daemon-reload 2>/dev/null || true

echo ""
echo "✓ ProvidAPT has been completely removed."
```

---

## Appendix A: Common Workflows

### Daily Health Check

```bash
#!/bin/bash
echo "ProvidAPT Health Check"
echo "======================"

# Check daemon
if pidof providaptd > /dev/null; then
    echo "✓ Daemon running (PID $(pidof providaptd))"
else
    echo "✗ Daemon NOT running"
    exit 1
fi

# Check BPF programs
BPF_COUNT=$(sudo bpftool prog list | grep -c "lsm")
echo "✓ LSM programs: $BPF_COUNT"

# Check data directory
LOG_COUNT=$(ls /var/log/providapt/providapt-*.ndjson 2>/dev/null | wc -l)
echo "✓ Event logs: $LOG_COUNT files"

# Check API
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/v1/status)
echo "✓ API status: $HTTP_STATUS"

# RocksDB size
DB_SIZE=$(du -sh /var/lib/providapt/store 2>/dev/null | cut -f1)
echo "✓ Database size: ${DB_SIZE:-empty}"

# Memory usage
MEM=$(ps -o rss= -p $(pidof providaptd) 2>/dev/null || echo 0)
echo "✓ Memory: $(( MEM / 1024 )) MB"

echo ""
echo "All checks passed."
```

### Incident Response Workflow

```bash
# 1. Query the suspicious process
PROVQL="MATCH (p:Process)-[:READ]->(f:File) WHERE f.path STARTSWITH '/etc' RETURN p.pid"

# 2. Assess impact
providapt-heal -pid $(pgrep -f "suspicious" | head -1) -output /tmp/impact.json

# 3. Block C2
providapt-heal -pid $(pgrep -f "suspicious" | head -1) -firewall -dry-run=false

# 4. Export evidence
curl -s "http://localhost:8080/api/v1/graph/export?pid=1234" > /tmp/evidence.json

# 5. Generate AI report
# (requires LLM configured)
```

### Integration with SIEM

```bash
# Export provenance events in real-time via gRPC
# Configure /etc/providapt/providapt.toml:
# {
#   "export": {
#     "server": "https://siem.internal:50051",
#     "agent_id": "webserver-01",
#     "batch_size": 100
#   }
# }
```
