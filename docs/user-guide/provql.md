# ProvQL Query Language Guide

**Provenance Query Language** | Syntax, Patterns, and Analyst Query Library

---

## 1. Language Overview

ProvQL is a Cypher-inspired query language for traversing provenance graphs. It enables SOC analysts to trace attack paths, identify lateral movement, and extract subgraphs for forensic analysis.

## 2. Syntax

```sql
MATCH <pattern>
[WHERE <conditions>]
[DURING <time_range>]
[FOLLOW <direction> <max_hops>]
RETURN <fields>
```

### 2.1 MATCH Clause

Pattern matching syntax:

```sql
-- Simple pattern: single node
MATCH p:Process WHERE p.comm = "bash" RETURN p

-- Edge traversal: source → target
MATCH p:Process → f:File WHERE p.comm = "curl" RETURN p, f

-- Two-hop traversal
MATCH p:Process → f:File → p2:Process RETURN p, f, p2

-- Labeled edge
MATCH p:Process -[r:wasGeneratedBy]→ f:File RETURN p, f, r
```

### 2.2 WHERE Clause

Conditions and filters:

```sql
-- Attribute comparison
WHERE p.uid = 0
WHERE p.comm IN ("bash", "zsh", "python3")
WHERE f.path LIKE "/etc/%"
WHERE n.dst_port = 4444

-- Taint checks
WHERE p.taint_level >= "HIGH"
WHERE p.tainted = true

-- Composite conditions
WHERE p.uid = 0 AND p.comm = "bash" AND p.ppid = 1
```

### 2.3 DURING Clause

Time-range filtering:

```sql
-- Absolute time
DURING "2026-05-28T00:00:00Z" TO "2026-05-28T23:59:59Z"

-- Relative time (last N minutes/hours)
DURING LAST 30 MINUTES
DURING LAST 1 HOUR

-- Specific window
DURING BETWEEN "2026-05-28T12:00:00Z" AND "2026-05-28T14:00:00Z"
```

### 2.4 FOLLOW Clause

Traversal direction and depth:

```sql
-- Forward propagation (source → target)
MATCH p:Process → f:File FOLLOW FORWARD 5

-- Reverse propagation (target → source)
MATCH f:File → p:Process FOLLOW REVERSE 3

-- Bidirectional
MATCH p:Process ↔ n:Network FOLLOW BOTH 10
```

### 2.5 RETURN Clause

Output specification:

```sql
-- Return full nodes
RETURN p, f

-- Return specific fields
RETURN p.id, p.comm, p.uid, f.path, e.relation

-- Return with aliases
RETURN p.comm AS process_name, f.path AS file_path

-- Aggregation
RETURN p.comm, count(*) AS occurrences
RETURN p.taint_level, count(DISTINCT p.id) AS unique_processes

-- Limit results
RETURN p, f LIMIT 100
```

---

## 3. Classic Query Examples

### 3.1 Trace Web Shell Intrusion

```sql
-- Find processes that accessed webshell.php via web server
MATCH
  w:Process WHERE w.comm IN ("apache2", "nginx", "httpd")
  -[r:wasGeneratedBy]→
  f:File WHERE f.path LIKE "%evil%.php"
  -[r2:used]→
  p:Process WHERE p.uid > 0
FOLLOW FORWARD 5
DURING LAST 24 HOURS
RETURN w.id, w.comm, f.path, p.id, p.comm, p.uid
```

### 3.2 SSH Lateral Movement Detection

```sql
-- Find SSH connections from non-standard source hosts
MATCH
  p:Process WHERE p.comm = "ssh" AND p.uid = 0
  -[r:used]→
  n:Network WHERE n.dst_port = 22
FOLLOW REVERSE 3
WHERE p.ppid NOT IN (1, systemd_pids)
RETURN p.id AS ssh_pid, p.ppid AS parent_pid,
       n.dst_ip AS target_ip, n.timestamp
```

### 3.3 Supply Chain Poisoning Backtrack

```sql
-- Trace all processes that executed files from a compromised package
MATCH
  pkg:Package WHERE pkg.name = "evil-package" AND pkg.version = "1.0.0"
  -[r:wasAttributedTo]→
  f:File
  -[r2:used]→
  p:Process
FOLLOW FORWARD 10
RETURN pkg.name, pkg.version, f.path, p.id, p.comm
       p.taint_level, p.supply_chain_risk
```

### 3.4 Memory Anomaly Detection

```sql
-- Find processes with fileless execution + shellcode attributes
MATCH
  p:Process WHERE p.fileless = true AND p.shellcode = true
FOLLOW BOTH 3
RETURN p.id, p.comm, p.pid, p.mem_trigger,
       p.mem_risk_level, p.mem_matches, p.confirmed_malicious
```

### 3.5 Cross-Host Blast Radius

```sql
-- Trace lateral movement across all known hosts
MATCH
  p:Process WHERE p.taint_level = "CRITICAL"
  -[r:wasInformedBy WHERE r.lateral_movement = true]→
  p2:Process
FOLLOW FORWARD 5
RETURN p.host_id AS source_host, p.comm AS source_proc,
       p2.host_id AS target_host, p2.comm AS target_proc,
       r.technique, r.timestamp
```

### 3.6 Data Exfiltration Chain

```sql
-- Find sensitive file reads followed by network connections
MATCH
  p:Process
  -[r1:used]→
  f:File WHERE f.path LIKE "/etc/%" OR f.path LIKE "/root/%"
MATCH
  p:Process
  -[r2:used]→
  n:Network WHERE n.dst_port = 443
FOLLOW FORWARD 2
RETURN p.id, p.comm, f.path AS sensitive_file,
       n.dst_ip AS exfil_target, n.dst_port
```

### 3.7 Honeytoken Trigger Investigation

```sql
-- Investigate which process triggered a honeytoken
MATCH
  p:Process WHERE p.honeypot_triggered = true
FOLLOW REVERSE 10
RETURN p.id, p.comm, p.honeypot_path, p.honeypot_type,
       p.confirmed_malicious, p.frozen, p.captured_cmdline
```

### 3.8 Supply Chain Risk Assessment

```sql
-- Find all high-risk binaries installed outside package manager
MATCH
  f:File WHERE f.supply_chain_risk IN ("high", "critical")
FOLLOW BOTH 2
RETURN f.path, f.package_name, f.package_version,
       f.package_manager, f.supply_chain_risk,
       f.signing_verified, f.suspect_chain
```

---

## 4. Distributed ProvQL (Global Queries)

In a distributed deployment, ProvQL queries are transparently decomposed:

```sql
-- Global query: trace across all hosts
MATCH p:Process WHERE p.host_id = "host-a"
  -[r:wasInformedBy WHERE r.lateral_movement = "ssh"]→
  p2:Process WHERE p2.host_id = "host-b"
RETURN p.host_id, p.comm, p2.host_id, p2.comm, r.timestamp
```

The query engine decomposes this into:
1. Query `host-a` for outbound SSH processes (MATCH on host-a)
2. Query stitch table for matching flows
3. Query `host-b` for inbound SSH processes (MATCH on host-b)
4. Join results on flow fingerprint + timestamp window

---

## 5. Output Formats

```sql
-- Default: JSON array
RETURN p.id, p.comm
-- [{"id":"p:1234","comm":"bash"}, {"id":"p:5678","comm":"curl"}]

-- Graph: subgraph (nodes + edges for visualization)
RETURN GRAPH p, f, n
-- {"nodes":[...], "edges":[...]}

-- Count: aggregate
RETURN count(*) AS total
-- {"total": 42}

-- Path: list of node IDs along traversal
RETURN PATH p, f, n
-- {"path": ["p:1234", "f:5000", "n:10.0.0.5:4444"]}
```
