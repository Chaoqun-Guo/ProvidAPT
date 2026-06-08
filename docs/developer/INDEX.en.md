# Developer Documentation

This section is intended for developers who wish to extend or integrate ProvidAPT.

## Documents

| Document | Description |
| --- | --- |
| [api-reference.md](api-reference.md) | gRPC API definitions: service interfaces, request/response formats, error codes |
| [data-schema.md](data-schema.md) | Protobuf schema specification: event types, node attributes, edge relationships |
| [changelog.md](changelog.md) | Version changelog |
| [upgrade-guide.md](upgrade-guide.md) | Version upgrade notes, schema migration, API compatibility |
| [testing.md](testing.md) | Testing guide: unit tests, integration tests, performance benchmarks |
| [release-readiness.md](release-readiness.md) | Final pre-release validation checklist |

## Quick Development

```bash
# Compile all eBPF programs
make v1-ebpf

# Compile all Go binaries
make v1-userspace

# Run unit tests
make v1-test
```

## Extension Guide

Basic steps for adding a new eBPF hook point:

1. Write the eBPF C program under `cmd/bpf/probes/`
2. Define the new event type in `cmd/bpf/headers/events.h`
3. Register the event handler in userspace `internal/engine/collector/`
4. Add the new event message to the Protobuf schema
