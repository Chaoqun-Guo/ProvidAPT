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

## Redaction

Fields containing paths, addresses, command lines, or environment-derived context may be masked according to configuration. Support bundles should be reviewed before external sharing.
