# Developer Documentation

This section is for engineers extending, integrating, testing, or releasing ProvidAPT.

## Documents

| Document | Description |
| --- | --- |
| [api-reference.md](api-reference.md) | gRPC and HTTP API definitions |
| [data-schema.md](data-schema.md) | Protobuf schema and relationship model |
| [testing.md](testing.md) | Unit, integration, and benchmark guidance |
| [upgrade-guide.md](upgrade-guide.md) | Release-line upgrade and rollback guide |
| [release-readiness.md](release-readiness.md) | Final pre-release checklist |
| [release-notes-v1.2.2.md](release-notes-v1.2.2.md) | `v1.2.2` release notes |
| [changelog.md](changelog.md) | Engineering-facing change log |

## Quick Development

```bash
make build-ebpf
make build-userspace
make test-core
```
