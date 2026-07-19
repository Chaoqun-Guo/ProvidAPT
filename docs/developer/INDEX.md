# Developer Documentation

This section is for developers and maintainers who extend, integrate, test, or release ProvidAPT.

## Documents

| Document | Description |
| --- | --- |
| [api-reference.md](api-reference.md) | gRPC and HTTP API definitions, request and response structures, and error codes |
| [openapi.yaml](openapi.yaml) | Machine-readable HTTP API contract for tooling and client generation |
| [config-reference.md](config-reference.md) | Configuration sections and major fields |
| [config.schema.json](config.schema.json) | Machine-readable configuration schema for validation and editors |
| [data-schema.md](data-schema.md) | Protobuf data model, event types, and relationship structure |
| [ebpf-dev.md](ebpf-dev.md) | eBPF development and loader guidance |
| [event-field-source.md](event-field-source.md) | Source layer for event, alert, audit, and SIEM fields |
| [storage-backends.md](storage-backends.md) | Pebble/local and PostgreSQL storage backend guidance |
| [dashboard-api.md](dashboard-api.md) | Dashboard panel to API endpoint mapping |
| [plugin-development.md](plugin-development.md) | Plugin extension model and integration points |
| [rule-engine-internals.md](rule-engine-internals.md) | Rule matching, correlation, severity, whitelist, and rollout internals |
| [testing.md](testing.md) | Unit, integration, and performance testing |
| [upgrade-guide.md](upgrade-guide.md) | Upgrade, preflight, and rollback guidance |
| [package-build.md](package-build.md) | Commercial Linux package lifecycle and installation asset requirements |
| [release-readiness.md](release-readiness.md) | Final pre-release checklist |
| [release-notes-v1.2.3-rc.1.md](release-notes-v1.2.3-rc.1.md) | Release notes for `v1.2.3-rc.1` |
| [release-notes-v1.2.2.md](release-notes-v1.2.2.md) | Release notes for `v1.2.2` |
| [release-notes-v1.2.1.md](release-notes-v1.2.1.md) | Release notes for `v1.2.1` |
| [changelog.md](changelog.md) | Engineering change log |

## Quick Development Commands

```bash
make build-ebpf
make build-userspace
make test-core
```
