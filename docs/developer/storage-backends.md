# Storage Backends

ProvidAPT uses local storage for agent evidence and PostgreSQL for production control-plane state.

## Backend Summary

| Backend | Use | Production Status |
| --- | --- | --- |
| Pebble / local files | local event store, evaluation, agent-side evidence | supported for local agent data |
| JSON file state | local control-plane testing | not recommended for production |
| PostgreSQL | fleet, policy, audit, HA, and operational metadata | recommended for production control plane |

## PostgreSQL

Use PostgreSQL when:

- multiple agents report to a server
- HA or active-passive control plane is enabled
- policy history and audit state must survive restarts
- customer backup and retention processes require database integration

Configuration uses a PostgreSQL DSN:

```yaml
control_plane:
  state_backend: postgresql://providapt:${PROVIDAPT_PG_PASSWORD}@postgres.example.com:5432/providapt?sslmode=require
```

## Local Store

Local paths are still used for:

- eBPF and graph evidence
- logs
- support bundles
- SIEM outbox
- local checkpoint backups

## Migration Guidance

- Start new production deployments on PostgreSQL.
- Treat file-backed control-plane state as evaluation-only.
- Back up PostgreSQL before upgrades.
- Validate restore in staging before production cutover.
- Capture `make ops-postgres-drill` output before release or migration windows;
  the JSON/Markdown reports redact DSNs and record backup, restore, schema, and
  PostgreSQL client tooling evidence.
