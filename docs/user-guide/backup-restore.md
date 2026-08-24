# Backup and Restore

This guide covers backup and restore workflows for configuration, local evidence, and production control-plane state.

## What to Back Up

| Data | Default Location | Notes |
| --- | --- | --- |
| configuration | `/etc/providapt/` | redact secrets before sharing |
| local event store | `/var/lib/providapt/` | stop service for cold file-level backup |
| logs and evidence | `/var/log/providapt/` | includes support bundles, compliance reports, and SIEM outbox |
| PostgreSQL | operator-provided DSN | required for production control-plane state |

## Create a Checkpoint Backup

From the API:

```bash
curl -X POST http://<server>:18080/api/v1/control/backup \
  -H "Content-Type: application/json" \
  -d '{"action":"create","note":"pre-maintenance backup"}'
curl -O http://<server>:18080/api/v1/control/backup/download
```

From the host:

```bash
sudo systemctl stop providapt.service
sudo tar czf providapt-host-backup.tar.gz /etc/providapt /var/lib/providapt /var/log/providapt
sudo systemctl start providapt.service
```

## PostgreSQL Backup

```bash
pg_dump "$PROVIDAPT_DATABASE_DSN" > providapt-control-plane.sql
```

Restore to a staging database first:

```bash
createdb providapt_restore_check
psql providapt_restore_check < providapt-control-plane.sql
```

Repeatable drill:

```bash
export PROVIDAPT_DATABASE_DSN='postgres://providapt:<password>@postgres.example.com:5432/providapt?sslmode=require'
export PROVIDAPT_RESTORE_DSN='postgres://providapt:<password>@restore.example.com:5432/providapt_restore?sslmode=require'
make ops-postgres-drill
```

If `PROVIDAPT_RESTORE_DSN` is unset, the drill still creates the logical backup
and reports that restore verification was skipped. Production release evidence
should include both backup creation and restore verification.
The drill also writes `build/postgres/postgres-drill.json` and
`build/postgres/postgres-drill.md` so release records can include structured
backup, restore, schema, and tooling evidence without exposing database
passwords.

## Staged Restore

Use the staged restore API when available:

```bash
curl -X POST http://<server>:18080/api/v1/control/backup \
  -H "Content-Type: application/json" \
  -d '{"action":"restore_staging"}'
```

Validate the staged data before cutover. Use `prepare_cutover` only during an approved maintenance window:

```bash
curl -X POST http://<server>:18080/api/v1/control/backup \
  -H "Content-Type: application/json" \
  -d '{"action":"prepare_cutover"}'
```

## Restore Checklist

- confirm the backup version and target version are compatible
- stop write traffic when restoring local stores
- preserve the failed state for support if incident analysis is required
- verify service health after restore
- verify fleet, policy, alert, and audit views
- document restore time, owner, and evidence
