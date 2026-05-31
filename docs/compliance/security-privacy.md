# Security, Compliance & Privacy

**Data Protection** | Self-Defense Mechanisms | Compliance Certifications

---

## 1. Data Privacy & Protection

### 1.1 Sensitive Data Masking

ProvidAPT provides configurable path and data masking to prevent sensitive information from being stored in the provenance graph:

```toml
# /etc/providapt/providapt.toml
[privacy]
# Mask file paths matching these patterns
mask_paths = [
  "/etc/shadow",
  "/etc/passwd",
  "/etc/ssl/private/*",
  "*.pem",
  "*.key",
]

# Mask environment variable values in captured context
mask_env_keys = [
  "AWS_SECRET_ACCESS_KEY",
  "DB_PASSWORD",
  "API_KEY",
  "TOKEN",
  "SECRET*",
]

# Maximum length for captured string values
max_string_length = 256

# Anonymize IP addresses (replace last octet with .0)
anonymize_ips = false
```

### 1.2 Path Masking

When a masked path is detected:
1. The path field is replaced with `<redacted>` in the event
2. The original path is NOT written to Pebble storage
3. The node label shows `<redacted: sensitive path>` 
4. A hash of the original path is stored for dedup (SHA256 truncated to 8 bytes)

```json
// Before masking
{"pathname": "/etc/shadow", "comm": "cat"}

// After masking
{"pathname": "<redacted: sensitive path>", "comm": "cat",
 "path_hash": "a3f8b2c1e4d5"}
```

### 1.3 Process Context Truncation

When capturing process context for frozen processes, the following limits apply:

| Field | Max Length | Notes |
|-------|-----------|-------|
| Environment variable value | 128 chars | Truncated with `...` |
| Cmdline | 4096 chars | Full command line |
| Memory maps | 50 entries | First 50 regions only |
| Open FDs | 50 entries | First 50 file descriptors |

---

## 2. Self-Defense Mechanisms

### 2.1 File Protection (eBPF LSM)

The `defense.bpf.c` program prevents unauthorized modification of ProvidAPT's data:

| Protection | Mechanism | Effect |
|-----------|-----------|--------|
| DB file protection | LSM file_permission hook | Denies write to `.sst` files by non-agent |
| Agent PID protection | `/proc` access control | Hides agent from non-root processes |
| Config file protection | Inode-level ACL | Prevents tampering with `.toml` files |
| Binary integrity | eBPF-based hashing | Detects binary replacement |

Protected inodes are registered at startup:
```c
// Only the agent and watchdog can write to these inodes
// All other processes (including root) receive -EPERM
SEC("lsm/file_permission")
int probe_protect_logs(struct file *file, int mask)
```

### 2.2 Agent Death Monitoring

The watchdog monitors agent liveness via eBPF `task_free` hook:

```c
// When an agent-tagged process exits, emit EV_AGENT_KILLED
// Records the killer PID from real_parent
SEC("lsm/task_free")
int probe_agent_death(struct task_struct *task)
```

### 2.3 Data Integrity Verification

Merkle tree anchoring provides tamper-evident storage:

```go
// Periodic root hashing
rootHash = SHA256(
    SHA256(leaf_count) +
    SHA256(rootHash_previous) +
    SHA256(last_timestamp)
)
// Root hash signed with agent's key and stored as anchor
```

Verification with `providapt-verify`:
```bash
providapt-verify -data /var/lib/providapt/store -verbose
# Output: ✓ No tampering detected (42 anchors verified)
```

### 2.4 CGroup Resource Isolation

The agent operates under cgroup v2 limits:

```
CPUQuota:   50% of one core
MemoryMax:  2 GB
MemorySwap: 0 (off)
```

Prevents the agent from impacting other system processes during event bursts.

---

## 3. Compliance

### 3.1 Data Retention

| Tier | Duration | Storage | Access |
|------|----------|---------|--------|
| Hot (in-memory) | Current scan | LRU cache (RAM) | Graph queries |
| Warm (local) | 7 days | Pebble (SSD) | ProvQL queries |
| Cool (local archive) | 3 months | Parquet (local) | Batch export |
| Cold (remote) | 6+ months | S3/Parquet | Request-based |

### 3.2 Data Sovereignty

| Feature | Description |
|---------|-------------|
| Local-first storage | All raw data stays on-premise |
| No telemetry | No external communication without explicit transport config |
| Audit log | All queries and exports logged |
| Deletion API | `DELETE /admin/purge` removes data by time range or case ID |

### 3.3 Audit Trail

All analyst interactions with the system are logged:

```json
{
  "timestamp": "2026-05-28T14:23:00Z",
  "user": "analyst@org.com",
  "action": "provql_query",
  "query": "MATCH p:Process WHERE p.taint_level = \"CRITICAL\"",
  "result_count": 12,
  "duration_ms": 45
}
```

### 3.4 Forensic Readiness

| Artifact | Location | Format |
|----------|----------|--------|
| Provenance graph | `/var/lib/providapt/store/` | JSON (Pebble) |
| Event log | `/var/log/providapt/providapt.log` | Text |
| eBPF programs | `/usr/local/lib/providapt/ebpf/*.bpf.o` | ELF/BPF |
| Configuration | `/etc/providapt/providapt.toml` | TOML |
| Frozen process context | `/sys/fs/cgroup/providapt-freeze/` | cgroup fs |
