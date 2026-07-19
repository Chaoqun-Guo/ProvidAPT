# Developer Documentation

This section is for engineers extending, integrating, testing, or releasing ProvidAPT.

## Documents

| Document | Description |
| --- | --- |
| [api-reference.md](api-reference.md) | gRPC and HTTP API definitions |
| [config-reference.md](config-reference.md) | Configuration sections and major fields |
| [data-schema.md](data-schema.md) | Protobuf schema and relationship model |
| [ebpf-dev.md](ebpf-dev.md) | eBPF development and loader guidance |
| [event-field-source.md](event-field-source.md) | Source layer for event, alert, audit, and SIEM fields |
| [storage-backends.md](storage-backends.md) | Pebble/local and PostgreSQL storage backend guidance |
| [dashboard-api.md](dashboard-api.md) | Dashboard panel to API endpoint mapping |
| [plugin-development.md](plugin-development.md) | Plugin extension model and integration points |
| [rule-engine-internals.md](rule-engine-internals.md) | Rule matching, correlation, severity, whitelist, and rollout internals |
| [testing.md](testing.md) | Unit, integration, and benchmark guidance |
| [upgrade-guide.md](upgrade-guide.md) | Release-line upgrade and rollback guide |
| [release-readiness.md](release-readiness.md) | Final pre-release checklist |
| [release-notes-v1.2.3-rc.1.md](release-notes-v1.2.3-rc.1.md) | `v1.2.3-rc.1` release notes |
| [release-notes-v1.2.2.md](release-notes-v1.2.2.md) | `v1.2.2` release notes |
| [release-notes-v1.2.1.md](release-notes-v1.2.1.md) | `v1.2.1` release notes |
| [changelog.md](changelog.md) | Engineering-facing change log |

## Quick Development

```bash
make build-ebpf
make build-userspace
make test-core
```
