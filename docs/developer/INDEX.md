# Developer Documentation

This section is for developers and maintainers who extend, integrate, test, or release ProvidAPT.

## Documents

| Document | Description |
| --- | --- |
| [api-reference.md](api-reference.md) | gRPC and HTTP API definitions, request and response structures, and error codes |
| [data-schema.md](data-schema.md) | Protobuf data model, event types, and relationship structure |
| [testing.md](testing.md) | Unit, integration, and performance testing |
| [upgrade-guide.md](upgrade-guide.md) | Upgrade, preflight, and rollback guidance |
| [package-build.md](package-build.md) | Commercial Linux package lifecycle and installation asset requirements |
| [release-readiness.md](release-readiness.md) | Final pre-release checklist |
| [release-notes-v1.2.2.md](release-notes-v1.2.2.md) | Release notes for `v1.2.2` |
| [changelog.md](changelog.md) | Engineering change log |

## Quick Development Commands

```bash
make build-ebpf
make build-userspace
make test-core
```
