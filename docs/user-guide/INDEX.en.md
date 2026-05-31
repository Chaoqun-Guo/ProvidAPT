# User Guide

This section provides detailed instructions for daily operations with ProvidAPT, covering CLI, query syntax, rule authoring, and visualization.

## Documents

| Document | Description |
| --- | --- |
| [cli.md](cli.md) | `providaptctl` command reference: parameters, subcommands, usage examples |
| [provql.md](provql.md) | ProvQL query syntax: graph traversal, time filtering, aggregation operations |
| [detection-rules.md](detection-rules.md) | Sigma rule writing guide: rule structure, field mapping, custom aggregation |
| [operations.md](operations.md) | Daily operations: log management, health checks, fault recovery |
| [visual-guide.md](visual-guide.md) | Visualization interface: dashboards, provenance graph browsing, event search |
| [manual.md](manual.md) | User Manual (English) [中文版](manual.zh.md) |
| [manual.zh.md](manual.zh.md) | 用户手册（中文完整版） |

## Typical Workflow

```bash
# Query recent alerts
providaptctl alert list --since 1h

# Trace provenance of a process
providaptctl provenance trace --pid 1234

# Check system health status
providaptctl status
```
