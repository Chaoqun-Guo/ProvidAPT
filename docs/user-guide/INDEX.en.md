# User Guide

This section provides detailed instructions for daily operations with ProvidAPT, covering CLI usage, query syntax, rule authoring, and visualization.

## Documents

| Document | Description |
| --- | --- |
| [cli.md](cli.md) | `providaptctl` command reference: parameters, subcommands, and usage examples |
| [rbac.md](rbac.md) | RBAC, API keys, tenant scoping, and trusted-header SSO |
| [api-auth.md](api-auth.md) | API authentication configuration and request examples |
| [grpc.md](grpc.md) | gRPC API usage and integration examples |
| [provql.md](provql.md) | ProvQL query syntax: graph traversal, time filtering, and aggregation operations |
| [detection-rules.md](detection-rules.md) | Detection rule guide: rule structure, field mapping, and custom aggregation |
| [policy-lifecycle.md](policy-lifecycle.md) | Policy draft, validation, approval, publish, rollout, and rollback |
| [fleet-management.md](fleet-management.md) | Agent enrollment, state, metadata, quarantine, and revocation |
| [backup-restore.md](backup-restore.md) | Configuration, evidence, local store, and PostgreSQL backup / restore |
| [upgrade-rollback.md](upgrade-rollback.md) | Operator upgrade, validation, and rollback procedures |
| [siem-integration.md](siem-integration.md) | SIEM configuration, delivery testing, field mapping, and troubleshooting |
| [operations.md](operations.md) | Daily operations: log management, health checks, and fault recovery |
| [troubleshooting.md](troubleshooting.md) | Common startup, eBPF, fleet, PostgreSQL, and SIEM issues |
| [visual-guide.md](visual-guide.md) | Visualization interface: dashboards, provenance graph browsing, and event search |
| [manual.md](manual.md) | Full user manual |

## Typical Workflow

```bash
# Query recent alerts
providaptctl alert list --since 1h

# Trace provenance of a process
providaptctl provenance trace --pid 1234

# Check system health status
providaptctl status
```
