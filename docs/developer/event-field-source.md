# Event Field Source Reference

This reference explains where commonly observed event and log fields originate.

## Source Layers

| Layer | Examples | Responsibility |
| --- | --- | --- |
| kernel / eBPF | PID, UID, command, file path, socket tuple | raw event capture |
| agent userspace | agent ID, hostname, timestamp normalization | enrichment and filtering |
| graph pipeline | node IDs, edge types, lineage | provenance construction |
| policy engine | severity, rule ID, alert ID | detection and scoring |
| control plane | actor, workflow state, approval ID | operator actions and audit |
| storage / SIEM | export timestamp, delivery state | persistence and integration |

## Common Fields

| Field | Source | Notes |
| --- | --- | --- |
| `pid` | eBPF task context | process ID at event time |
| `ppid` | eBPF or userspace enrichment | parent process when available |
| `comm` | kernel task command | short process name |
| `uid` / `gid` | kernel credentials | numeric identity |
| `path` | file hook or userspace enrichment | may be redacted |
| `src_addr` / `dst_addr` | socket hooks | may be anonymized |
| `agent_id` | agent configuration or generated identity | stable fleet identity |
| `hostname` | agent host metadata | control-plane display |
| `node_id` | provenance graph | stable graph reference |
| `edge_type` | graph pipeline | READ, WROTE, EXEC, CONNECTED, and related relations |
| `severity` | policy engine or workflow | INFO, WARNING, HIGH, CRITICAL depending on source |
| `alert_id` | alert pipeline | workflow identifier |
| `actor` | control plane | authenticated API identity |
| `tenant` | RBAC mapping or metadata | fleet group / tenant scope |

## Stored Event Layout

ProvidAPT event NDJSON uses a normalized layout:

| Section | Source | Purpose |
| --- | --- | --- |
| `schema_version` | agent userspace | storage compatibility marker |
| `type` / `type_id` | eBPF event kind mapped by the collector | stable event classification |
| `timestamp_ns` | kernel timestamp, normalized in userspace | ordering and graph construction |
| `process` | eBPF task context plus userspace `/proc` enrichment | PID, TID, PPID, UID, GID, `comm`, executable, and command line |
| `payload` | event-type-specific eBPF fields | file, process, network, sample, or generic event body |
| `enrich` | userspace enrichment | hostname, agent ID, observed path aliases, policy context, and derived labels when available |
| `raw` | original collector event | compatibility and troubleshooting for low-level fields |

Typed payloads keep overloaded kernel fields out of the analyst view:

| Event family | Payload fields |
| --- | --- |
| process fork/exec/exit | `child_pid`, `parent_pid`, `exit_code`, `exe_path`, `cmdline` when available |
| file open/read/write/unlink | `pathname`, `inode`, `dev_major`, `dev_minor`, `mode`, `flags` |
| network connect/accept | `src_addr`, `dst_addr`, `src_port`, `dst_port`, `protocol` |
| scheduler/sample events | `sample_hook_id`, `sample_count` |
| unknown or legacy events | `raw_fields` with the original numeric values |

Older flat records are still accepted by replay and search paths. New integrations should read the normalized sections first and use `raw` only when diagnosing collector-level behavior.

## Redaction

Fields containing paths, addresses, command lines, or environment-derived context may be masked according to configuration. Support bundles should be reviewed before external sharing.
