# Provenance Data Model

## Node Types

| Type | Meaning | Example |
|------|---------|---------|
| `process` | Process (PID/TID) | nginx worker #1234 |
| `file` | File/Directory (inode) | /etc/passwd |
| `net` | Network endpoint (IP:Port) | 10.0.0.1:443 |
| `ipc` | Inter-process communication (pipe/shmem) | pipe:[12345] |
| `credential` | Credential change | setuid/apparmor |

## Edge Types

| Type | Meaning | Typical Scenario |
|------|---------|------------------|
| `fork` | Process fork | Shell executes command |
| `execute` | Process execution | execve loads binary |
| `read` | Process reads file | Reading configuration file |
| `write` | Process writes file | Writing log / malicious file |
| `connect` | Outbound connection | C2 communication |
| `accept` | Listen/accept connection | Reverse shell |
| `send/recv` | Network data transfer | Data exfiltration |

## W3C PROV-DM Mapping

ProvidAPT follows the W3C PROV Data Model (PROV-DM) for provenance graph construction:

### Node Mapping

| PROV Type | ProvidAPT Type | Description |
|-----------|---------------|-------------|
| `prov:Activity` | `process` | Computational activity (process) |
| `prov:Entity` | `file`, `net`, `ipc`, `memory` | Digital entity |
| `prov:Agent` | `credential` | User/identity context |

### Edge Mapping

| PROV Relation | ProvidAPT Relation | Semantics |
|--------------|-------------------|-----------|
| `prov:used` | `read`, `connect`, `execute` | Activity consumed entity |
| `prov:wasGeneratedBy` | `write` | Entity produced by activity |
| `prov:wasInformedBy` | `fork`, `ipc` | Activity communication |
| `prov:wasDerivedFrom` | `version` | Entity derived from entity |
| `prov:hadSecurityContext` | `setuid` | Activity bound to credential |

## APT Detection Relationships

Example provenance path during an attack:

```
attacker.sh (exec)
  → bash (fork)
    → curl (exec)
      → connect(c2.attacker.com:443)  [C2 communication]
    → chmod (exec)
      → write(/tmp/malware)           [File drop]
    → /tmp/malware (exec)
      → connect(c2.attacker.com:8443) [Second stage]
      → read(/etc/shadow)             [Privilege escalation / credential theft]
```

## Graph Storage Structure

The provenance graph is stored as a directed acyclic graph (DAG) with the following characteristics:

- **In-Memory Cache**: Hot nodes (recently active) stored in LRU cache (8,192 nodes)
- **Cold Storage**: Evicted nodes persisted to Pebble (RocksDB-compatible) key-value store
- **Edge Indexing**: Primary index by timestamp for time-range queries, reverse index for impact analysis
- **Versioning**: File entities maintain version chains (`wasDerivedFrom`) tracking write history
