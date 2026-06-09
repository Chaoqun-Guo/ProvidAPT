# Examples

This directory contains practical ProvidAPT usage examples for local testing, API integration, and operator workflows.

## Included Examples

- `basic-capture/` — minimal eBPF ring-buffer capture example
- `client-status/` — Go client example for querying daemon status
- `supportbundle-api/` — API examples for support bundle export and download
- `provql/` — ready-to-use ProvQL investigation queries
- `config/` — example configuration snippets for local evaluation

## How to Use

- Start with `client-status/` if you want a simple API integration example
- Use `supportbundle-api/` for curl-based operator automation
- Use `provql/queries.sql` as a starter set for investigations
- Use `config/providapt.local.toml` as a baseline for a non-production lab setup
