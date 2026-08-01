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

## Build Directory Rules

`build/` contains both tracked build assets and ignored generated output.

Tracked assets:

- `build/*.sh` for local environment checks, dependency installation, and deployment helpers
- `build/*.toml` for default local development configuration
- `build/docker/` for Docker build definitions
- `build/packages/` for Debian, RPM, and tarball packaging helpers

Ignored generated output:

- `build/bin/` for compiled userspace binaries
- `build/ebpf/` for compiled eBPF objects
- `build/coverage/`, evaluation datasets, release reports, and temporary validation evidence

Use `.tmp-*` for short-lived test scratch directories.

## Documentation Placement Rules

| Path | Content Type |
| --- | --- |
| `docs/getting-started/` | Installation and first-run guidance |
| `docs/user-guide/` | Operator and analyst documentation |
| `docs/architecture/` | Architecture and data-model references |
| `docs/developer/` | API, schema, testing, release, and upgrade docs |
| `docs/project/` | Repository governance, documentation audit, release evidence, handoff, and release consistency |
| `docs/benchmarks/` | Performance reports |
| `docs/compliance/` | Security, privacy, and compliance posture |

## Root-Level Markdown Policy

Keep only the following document classes at repository root:

- product entry points such as `README.md` and `CHANGELOG.md`
- legal and governance documents such as `LICENSE`, `EULA.md`, `DPA.md`,
  `PRIVACY.md`, `SECURITY.md`, `CLA.md`, `CODE_OF_CONDUCT.md`, and
  `CONTRIBUTING.md`

All new long-form documentation, progress records, release evidence, and
roadmaps should be created under `docs/`. Use `docs/project/` for internal
handoff and release-management material.
