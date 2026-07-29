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
| `api.auth_tenants` | maps keys to fleet groups or tenants; use comma-separated values for managed multi-tenant scopes |
| `api.cors_origins` | allowed browser origins |

## AI Analysis

| Field | Purpose |
| --- | --- |
| `ai.provider` | LLM provider, usually `ollama` or `openai` |
| `ai.endpoint` | chat completion endpoint |
| `ai.model` | model name |
| `ai.timeout` | per-request timeout |
| `ai.max_retries` | transient retry count before fallback or error |
| `ai.retry_backoff` | base retry backoff, e.g. `250ms` |
| `ai.circuit_breaker_threshold` | consecutive failures before skipping provider calls |
| `ai.circuit_breaker_cooldown` | how long the LLM circuit remains open |
| `ai.max_prompt_bytes` | maximum prompt payload sent to the provider |
| `ai.fallback_without_llm` | returns deterministic local guidance when the provider is unavailable |

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
| `output.retain_files` | number of event NDJSON files to retain when byte retention is disabled; use `0` with `retain_max_bytes` |
| `output.retain_max_bytes` | total event NDJSON retention budget; when set, byte-budget pruning takes precedence over `retain_files` |
| `output.alert_max_file_bytes` | maximum `alerts.ndjson` size before rotation; `0` uses the built-in default |
| `output.alert_retain_files` | number of alert archives to retain when byte retention is disabled; use `0` with `alert_retain_max_bytes` |
| `output.alert_retain_max_bytes` | total alert NDJSON retention budget; keeps rotated alert files readable by the dashboard |
| `storage.encryption_enabled` | enables local storage encryption where supported |
| `control_plane.state_backend` | local state file path, `local`, or `postgresql://...` DSN for HA/fleet/policy state |

For a production-style local control plane, run PostgreSQL with Docker and use
the DSN directly in `control_plane.state_backend`:

```yaml
control_plane:
  mode: active-passive
  node_id: control-plane-1
  role: leader
  state_backend: postgresql://providapt:change-me@127.0.0.1:5432/providapt?sslmode=disable
```

For constrained VMs, start with:

```yaml
output:
  max_file_bytes: 16777216
  retain_files: 0
  retain_max_bytes: 268435456
  alert_max_file_bytes: 8388608
  alert_retain_files: 0
  alert_retain_max_bytes: 67108864
```

For production hosts with enough disk, keep 4 GiB of event NDJSON while still
rotating individual files:

```yaml
output:
  max_file_bytes: 67108864
  retain_files: 0
  retain_max_bytes: 4294967296
  alert_max_file_bytes: 16777216
  alert_retain_files: 0
  alert_retain_max_bytes: 268435456
```

## Policy

| Field | Purpose |
| --- | --- |
| `policy.endpoint` | control-plane endpoint for policy bundle pulls |
| `policy.api_key` | API key for policy operations |
| `policy.bundle_dir` | applied policy bundle cache |

## Secrets

| Field | Purpose |
| --- | --- |
| `secrets.provider` | `env`, `file`, or `vault` reference resolver |
| `secrets.base_dir` | base directory for relative `file:<name>` secret references |
| `secrets.vault` | config-managed Vault material map used by `vault:<key>` references |

Sensitive fields such as `policy.api_key`, `siem.token`,
`license.signing_key`, and notification credentials can use:

```yaml
secrets:
  provider: vault
  base_dir: /run/secrets/providapt
  vault:
    policy/api-key: "injected-by-config-management"
policy:
  api_key: vault:policy/api-key
siem:
  token: file:siem-token
```

## TLS Rotation

| Field | Purpose |
| --- | --- |
| `tls.rotation_check` | automatic rotation check interval, for example `24h` |
| `tls.rotation_renew_before` | rotate when the certificate expires within this window |
| `tls.rotation_auto` | enables scheduled server certificate rotation |
| `tls.rotation_restart_after` | records whether operators should restart services after rotation |

Manual rotation is available from the security control action
`rotate_server_cert`; automatic rotation uses the same CA and writes audit
history when enabled.

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
