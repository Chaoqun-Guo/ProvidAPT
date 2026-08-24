# User Guide

This section explains daily ProvidAPT operations, including CLI usage, queries, rules, operations, and visualization.

## Documents

| Document | Description |
| --- | --- |
| [cli.md](cli.md) | `providaptctl` and related command reference |
| [rbac.md](rbac.md) | Open-source access control, RBAC roles, and trusted-header SSO |
| [grpc.md](grpc.md) | gRPC API usage and integration examples |
| [provql.md](provql.md) | ProvQL query syntax and examples |
| [detection-rules.md](detection-rules.md) | Detection rule authoring |
| [policy-lifecycle.md](policy-lifecycle.md) | Policy draft, validation, approval, publish, rollout, and rollback |
| [fleet-management.md](fleet-management.md) | Agent enrollment, state, metadata, quarantine, and revocation |
| [backup-restore.md](backup-restore.md) | Configuration, evidence, local store, and PostgreSQL backup / restore |
| [upgrade-rollback.md](upgrade-rollback.md) | Operator upgrade, validation, and rollback procedures |
| [siem-integration.md](siem-integration.md) | SIEM configuration, delivery testing, field mapping, and troubleshooting |
| [operations.md](operations.md) | Operations, health checks, and troubleshooting |
| [troubleshooting.md](troubleshooting.md) | Common startup, eBPF, fleet, PostgreSQL, and SIEM issues |
| [visual-guide.md](visual-guide.md) | UI and graph exploration guide |
| [manual.md](manual.md) | Complete user manual |

## Common Tasks

```bash
providaptctl alert list --since 1h
providaptctl provenance trace --pid 1234
providaptctl status
```
