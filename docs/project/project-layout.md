# Project Layout

This document defines where files belong in the ProvidAPT repository.

## Top-Level Directories

| Path | Purpose |
| --- | --- |
| `cmd/` | Executable entry points |
| `internal/` | Private implementation packages |
| `pkg/` | Reusable public packages |
| `docs/` | Structured documentation by audience |
| `deploy/` | Deployment manifests and infrastructure examples |
| `scripts/` | Operational and maintenance scripts |
| `test/` | Integration, validation, and benchmark assets |
| `build/` | Build-time, packaging, and container assets |
| `examples/` | Sample configuration and usage patterns |

## Documentation Placement Rules

| Path | Content Type |
| --- | --- |
| `docs/getting-started/` | Installation and first-run guidance |
| `docs/user-guide/` | Operator and analyst documentation |
| `docs/architecture/` | Architecture and data-model references |
| `docs/developer/` | API, schema, testing, release, and upgrade docs |
| `docs/project/` | Repository governance, documentation audit, release consistency |
| `docs/benchmarks/` | Performance reports |
| `docs/compliance/` | Security, privacy, and compliance posture |

## Root-Level Markdown Policy

Keep only the following document classes at repository root:

- product entry points such as `README.md` and `CHANGELOG.md`
- legal and governance documents such as `LICENSE`, `EULA.md`, `DPA.md`, `SECURITY.md`, `CLA.md`
- short-lived engineering logs only when they are intentionally top-level (`DEVELOPMENT_PROGRESS.md`, `COMMERCIALIZATION_ROADMAP.md`)

All new long-form documentation should be created under `docs/`.
