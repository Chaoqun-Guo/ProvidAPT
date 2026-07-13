# User Guide

This section provides detailed instructions for daily operations with ProvidAPT, covering CLI usage, query syntax, rule authoring, and visualization.

## Documents

| Document | Description |
| --- | --- |
| [cli.md](cli.md) | `providaptctl` command reference: parameters, subcommands, and usage examples |
| [provql.md](provql.md) | ProvQL query syntax: graph traversal, time filtering, and aggregation operations |
| [detection-rules.md](detection-rules.md) | Detection rule guide: rule structure, field mapping, and custom aggregation |
| [operations.md](operations.md) | Daily operations: log management, health checks, and fault recovery |
| [visual-guide.md](visual-guide.md) | Visualization interface: dashboards, provenance graph browsing, and event search |
| [manual.md](manual.md) | Full user manual |

## Typical Workflow

```bash
# Query recent alerts
providaptctl alert list --since 1h

# Trace provenance of a process
providaptctl provenance trace --pid 1234

# Check system health status
providaptctl status
```
