# Configuration Reference

This reference summarizes the major ProvidAPT configuration sections. Use `providaptctl -config-check` to validate an environment-specific file. For editor integration and automated validation, use the machine-readable schema in [config.schema.json](config.schema.json).

## API

| Field | Purpose |
| --- | --- |
| `api.rest` | REST dashboard/API listener |
| `api.grpc` | gRPC telemetry/API listener |
| `api.auth_enabled` | enables API key or trusted-header authorization |
| `api.auth_keys` | accepted API keys |
| `api.auth_roles` | maps keys to roles |
| `api.auth_tenants` | maps keys to fleet groups or tenants |
| `api.cors_origins` | allowed browser origins |

## Capture

| Field | Purpose |
| --- | --- |
| `capture.include_comms` | allow-list process command names before events enter the graph |
| `capture.detail_level` | controls event detail and high-frequency hook behavior |

## Storage

| Field | Purpose |
| --- | --- |
| `output.dir` | local log and evidence directory |
| `output.format` | event export format, usually `json` for NDJSON |
| `output.max_file_bytes` | maximum active event NDJSON file size before rotation; `0` uses the built-in default |
| `output.retain_files` | number of event NDJSON files to retain, including the active file; use `1` for small disks |
| `output.alert_max_file_bytes` | maximum `alerts.ndjson` size before rotation; `0` uses the built-in default |
| `output.alert_retain_files` | number of alert archives to retain; the active `alerts.ndjson` is always kept |
| `storage.encryption_enabled` | enables local storage encryption where supported |
| `control_plane.state_backend` | file or PostgreSQL-backed control-plane state |

For constrained VMs, start with:

```yaml
output:
  max_file_bytes: 16777216
  retain_files: 1
  alert_max_file_bytes: 8388608
  alert_retain_files: 1
```

## Policy

| Field | Purpose |
| --- | --- |
| `policy.endpoint` | control-plane endpoint for policy bundle pulls |
| `policy.api_key` | API key for policy operations |
| `policy.bundle_dir` | applied policy bundle cache |

## Backup and Compliance

| Field | Purpose |
| --- | --- |
| `backup.enabled` | automatic checkpoint backup |
| `backup.interval` | backup interval |
| `backup.retain_archives` | number of backup archives to keep |
| `compliance.retention_days` | audit/evidence retention period |
| `compliance.require_approvals` | require approvals for high-risk actions |

## SIEM

| Field | Purpose |
| --- | --- |
| `siem.enabled` | enables SIEM delivery |
| `siem.provider` | `generic`, `splunk`, or `elastic` |
| `siem.endpoint` | delivery endpoint |
| `siem.token` | token or `env:<NAME>` reference |
| `siem.min_severity` | minimum event severity |
| `siem.outbox_dir` | retry queue path |

## Upgrade and License

| Field | Purpose |
| --- | --- |
| `upgrade.download_url` | approved package URL |
| `upgrade.expected_sha256` | package digest |
| `upgrade.signature_path` | package signature |
| `upgrade.apply_command` | operator-approved apply command |
| `upgrade.rollback_command` | operator-approved rollback command |
| `license.path` | license document path |
| `license.public_key_path` | license public key |

See `examples/config/providapt.production.yaml` for a production-oriented template.
