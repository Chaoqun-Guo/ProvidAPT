# Data Schema & Model Specification

**Version 2.2** | Protobuf Definitions, Storage Encoding, Graph Schema

---

## 1. Wire Format 鈥-eBPF Ring Buffer Event (332 bytes)

The kernel-userspace communication uses a fixed-size packed struct defined in `cmd/bpf/headers/providapt.h`:

```
Offset  Size  Field          Type      Description
鈹€鈹€鈹€鈹€鈹€鈹€  鈹€鈹€鈹€鈹€  鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€  鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€  鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
     0     4  type           u32       Event type enum (see 搂1.1)
     4     4  flags          u32       Event flags (see 搂1.2)
     8     8  timestamp_ns   u64       Monotonic clock (bpf_ktime_get_ns)
    16     4  pid            u32       Process ID
    20     4  tid            u32       Thread ID
    24     4  ppid           u32       Parent PID
    28     4  uid            u32       User ID
    32     4  gid            u32       Group ID
    36    24  payload        union     Event-specific data
    60     4  sample_hook_id u32       (EV_SAMPLE only)
    64     4  sample_count   u32       (EV_SAMPLE only)
    60    16  comm           char[16]  Process name (null-terminated)
    76   256  pathname       char[256] File path / memfd name / C2 IP
    鈹€鈹€鈹€鈹€                                    鈹€鈹€鈹€鈹€鈹€
    332 total bytes (__attribute__((packed)))
```

### 1.1 Event Type Constants

```c
// Process life cycle (1-3)
EV_PROCESS_FORK      = 1    // task_alloc LSM hook
EV_PROCESS_EXEC      = 2    // bprm_check_security LSM hook
EV_PROCESS_EXIT      = 3    // task_free LSM hook

// File operations (10-14)
EV_FILE_OPEN         = 10   // file_open LSM hook
EV_FILE_CREATE       = 11   // file_open + O_CREAT
EV_FILE_MODIFY       = 12   // file_open + O_WRONLY/O_RDWR
EV_FILE_DELETE       = 13   // do_unlinkat kprobe
EV_FILE_RENAME       = 14   // rename tracepoint

// Network events (20-23)
EV_NET_CONNECT       = 20   // socket_connect LSM hook
EV_NET_ACCEPT        = 21   // socket_accept LSM hook
EV_NET_SEND          = 22
EV_NET_RECV          = 23

// Credential events (40-41)
EV_CRED_SETUID       = 40   // bprm_check + setuid
EV_CRED_CAPABLE      = 41   // security_capable kprobe

// Memory events (50-53)
EV_MEMFD_CREATE      = 50   // memfd_create tracepoint
EV_MPROTECT_RX       = 51   // mprotect RW鈫扲X
EV_PIPE_WRITE        = 52   // pipe write tracepoint
EV_PIPE_READ         = 53   // pipe read tracepoint

// Defensive events (200-211)
EV_AGENT_KILLED      = 200  // Agent process terminated
EV_FILE_DENIED       = 201  // Unauthorized file access denied
EV_HONEYPOT_TRIGGER  = 210  // Honeytoken path accessed
EV_HONEYPOT_LIST     = 211  // Honeytoken directory listed

// Aggregated (100)
EV_SAMPLE            = 100  // Adaptive sampling aggregate
```

### 1.2 Event Flags

```c
EV_FLAG_NONE        = 0
EV_FLAG_FROM_USER   = 1 << 0  // Userspace-originated operation
EV_FLAG_IS_ROOT     = 1 << 1  // Process running as root (uid=0)
EV_FLAG_EXEC_SETUID = 1 << 2  // setuid transition during exec
```

### 1.3 Payload Union Layout

```
File events (type 10-14):
  offset 36: inode      (u64) 鈥-file inode number
  offset 44: dev_major  (u32) 鈥-major device number
  offset 48: dev_minor  (u32) 鈥-minor device number
  offset 52: mode       (u32) 鈥-file mode
  offset 56: f_flags    (u32) 鈥-open flags

Fork events (type 1):
  offset 36: child_pid  (u32) 鈥-PID of child process
  offset 40: pad        ([20]byte)

Network events (type 20-23):
  offset 36: saddr      (u32) 鈥-source IPv4
  offset 40: daddr      (u32) 鈥-destination IPv4
  offset 44: sport      (u16) 鈥-source port
  offset 48: dport      (u16) 鈥-destination port
  offset 50: protocol   (u8)  鈥-IP protocol (6=TCP, 17=UDP)
```

---

## 2. Pebble Storage Schema

### 2.1 Key-Value Encoding

ProvidAPT uses CockroachDB Pebble with lexicographically sortable string keys.

| Key Prefix | Schema | Content |
|------------|--------|---------|
| `n:` | `n:<node_id>` | Node JSON |
| `e:` | `e:<ts_hex20>:<source>:<target>` | Edge JSON (time-order) |
| `r:` | `r:<target>:<ts_hex20>:<source>` | Edge reverse index |
| `b:` | `b:<hash>` | Baseline marker |
| `anchor:` | `anchor:<timestamp>` | Merkle root anchor |
| `evidence:` | `evidence:<case_id>` | Forensic evidence record |
| `filter:` | `filter:baseline` | Baseline hash set (JSON) |
| `cold:` | `cold:<entity_id>` | Archived data pointer |

### 2.2 Node Storage Format

```json
// Process node
{
  "id": "p:1234",
  "prov_type": "prov:Activity",
  "subtype": "process",
  "label": "bash",
  "first_seen": "2026-05-28T12:00:00Z",
  "last_seen": "2026-05-28T12:00:05Z",
  "attributes": {
    "pid": 1234, "uid": 1000, "comm": "bash",
    "taint_level": "CRITICAL",
    "fileless": true,
    "supply_chain_risk": "critical",
    "package_name": "evil-package"
  }
}

// File node with supply chain metadata
{
  "id": "f:5000:8:3",
  "prov_type": "prov:Entity",
  "subtype": "file",
  "label": "/usr/bin/nginx",
  "attributes": {
    "inode": 5000, "mode": "100755",
    "package_name": "nginx",
    "package_version": "1.24.0-1",
    "package_manager": "apt",
    "sbom_ref": "pkg:deb/debian/nginx@1.24.0-1",
    "signing_verified": "true",
    "artifact_hash": "sha256:abc123..."
  }
}
```

### 2.3 Edge Storage Format

```json
{
  "source": "p:100",
  "target": "f:5000:8:3",
  "relation": "prov:used",
  "count": 42,
  "timestamp": "2026-05-28T12:00:00Z",
  "attributes": {
    "technique": "T1105",
    "tainted": true
  }
}
```

Time-range query example:
```go
startKey = fmt.Sprintf("e:%020x", T1.UnixNano())
endKey   = fmt.Sprintf("e:%020x", T2.UnixNano())
// Pebble prefix scan on [startKey, endKey)
```

---

## 3. Global Graph Schema

### 3.1 GlobalNode (Central Server Format)

```go
type GlobalNode struct {
    ID        string                 // "p:<pid>", "f:<inode>"
    Type      string                 // "process", "file", "network", "memory"
    Label     string                 // comm, path, IP
    HostID    string                 // originating host
    AgentID   string                 // originating agent
    Props     map[string]interface{} // domain-specific attributes
    CreatedAt time.Time
}
```

### 3.2 GlobalEdge

```go
type GlobalEdge struct {
    Source   string
    Target   string
    Relation string            // "prov:used", "prov:wasGeneratedBy", etc.
    HostID   string
    Props    map[string]interface{}
    Time     time.Time
}
```

### 3.3 GraphDB Interface

```go
type GraphDB interface {
    CreateNode(nodeType, id, label string, props map[string]interface{}) (string, error)
    CreateEdge(sourceID, targetID, relation string, props map[string]interface{}) (string, error)
    QueryNodes(label string, props map[string]interface{}) ([]map[string]interface{}, error)
    QueryPaths(sourceID, targetID string, maxHops int) ([]map[string]interface{}, error)
    Close() error
}
```

### 3.4 Global Indexes

```go
type GlobalIndex struct {
    byHostID map[string]map[string]*IndexEntry  // hostID 鈫-{nodeID 鈫-entry}
    byIP     map[string]map[string]*IndexEntry  // IP 鈫-{nodeID 鈫-entry}
    byIdent  map[string]map[string]*IndexEntry  // identity 鈫-{nodeID 鈫-entry}
}
```

Backtrack query: `GlobalBacktrack(nodeID)` returns host path for a given node, enabling cross-host origin tracing.

---

## 4. Stitch Table Schema

The `StitchTable` matches cross-host TCP flows using a 5-tuple fingerprint:

```go
type FlowFingerprint struct {
    SrcIP       string
    DstIP       string
    SrcPort     uint32
    DstPort     uint32
    TCPSeq      uint32  // initial sequence number
    Timestamp   uint64  // TSval from TCP options
}

type StitchEdge struct {
    FlowID      string
    SourceHost  string
    TargetHost  string
    PID         uint32
    Comm        string
    Relation    string   // "remote_call" or "lateral_move"
    Tainted     bool
    Timestamp   time.Time
}
```

Matching rule: outbound and inbound flows match if fingerprint scores 鈮-3/5 fields, within 30-second window.

---

## 5. Graph Feature Vector Schema

The compact feature vector for anomaly detection and clustering:

```json
{
  "ts_ns": 1743123456000000000,
  "node_count": 1500,
  "edge_count": 4200,
  "density": 0.00187,
  "in_out_ratio": 0.85,
  "degree_dist": {"1": 800, "2": 400, "3": 200, "5": 50, "10": 50},
  "degree_stats": {"min": 1, "max": 10, "mean": 2.8, "median": 2, "std_dev": 1.5},
  "path_stats": {"max_depth": 7, "avg_depth": 3.2, "component_count": 42},
  "node_type_dist": {"process": 500, "file": 800, "network": 200},
  "edge_type_dist": {"prov:used": 3000, "prov:wasGeneratedBy": 1000, "prov:wasInformedBy": 200},
  "entropy_score": 1.42,
  "kl_divergence": 0.15,
  "is_anomaly": false
}
```

---

## 6. Protobuf Definitions (v2)

### 6.1 Node

```protobuf
message Node {
  string id = 1;                    // "p:<pid>", "f:<inode>:<dev>"
  string type = 2;                  // "process", "file", "network", ...
  string label = 3;                 // comm / pathname / address
  uint64 first_seen_ns = 4;
  uint64 last_seen_ns = 5;
  uint32 pid = 10; uint32 ppid = 11; uint32 uid = 12;
  string comm = 13;
  uint64 inode = 20; uint32 dev_major = 21; uint32 dev_minor = 22;
  uint32 mode = 23; uint32 f_flags = 24;
  string identity = 30; string session_id = 31;
  string source_ip = 32;
  map<string, string> attrs = 40;   // Domain-specific metadata
  uint32 monitor_level = 50;        // eBPF sampling detail level
}
```

### 6.2 Edge

```protobuf
message Edge {
  string id = 1;
  string source = 2; string target = 3;
  string relation = 4;             // "used", "wasGeneratedBy", ...
  uint64 timestamp_ns = 5;
  uint32 count = 6;                // Merge window counter
  float weight = 7;                // Edge weight for scoring
}
```

### 6.3 Event

```protobuf
message Event {
  uint32 type = 1; uint32 flags = 2; uint64 timestamp_ns = 3;
  uint32 pid = 4; uint32 tid = 5; uint32 ppid = 6;
  uint32 uid = 7; uint32 gid = 8;
  string comm = 9; string pathname = 10;
  // File fields
  uint64 inode = 20; uint32 dev_major = 21; uint32 dev_minor = 22;
  uint32 mode = 23; uint32 f_flags = 24; uint32 child_pid = 25;
  // Network fields
  uint32 saddr = 26; uint32 daddr = 27; uint32 sport = 28;
  uint32 dport = 29; uint32 protocol = 30;
}
```

### 6.4 gRPC Transport

```protobuf
service ProvidAPTTelemetry {
  rpc ReportEvents(stream CompressedEvent) returns (ReportAck);
}

message CompressedEvent {
  bytes  payload = 1;         // Zstd-compressed data
  string content_type = 2;    // "proto/edge", "proto/node", "proto/event"
  uint64 original_size = 3;   // Pre-compression size
  uint64 timestamp_ns = 4;
}

message ReportAck {
  uint32 accepted = 1;        // Events accepted
  uint32 throttle_level = 2;  // 0=normal, 1=slow, 2=backpressure
  string message = 3;
}
```

---

## 7. Taint Flag Encoding

Per-process taint flags stored in `taint_map` (BPF_MAP_TYPE_HASH, key=u32 pid, value=u32 bitmask):

```c
TAINT_NONE         = 0
TAINT_NET_CONNECT  = 1 << 0  // (1) 鈥-external IP connection
TAINT_FILE_WRITE   = 1 << 1  // (2) 鈥-sensitive path modified
TAINT_SETUID       = 1 << 2  // (4) 鈥-privilege escalation
TAINT_PARENT       = 1 << 3  // (8) 鈥-inherited from parent
TAINT_HONEYPOT     = 1 << 4  // (16) 鈥-honeytoken triggered
```

Detail levels (determine sampling rate in eBPF):
```c
DETAIL_CORE   = 0  // fork + exec only
DETAIL_NORMAL = 1  // + file_open, socket_connect
DETAIL_FULL   = 2  // all events including file_permission
```
