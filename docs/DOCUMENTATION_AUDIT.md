# Documentation Audit

This file groups the current documentation by audience and purpose so release reviews can navigate the repo more quickly.

## Product Entry Points

- `README.md` - project overview, navigation, feature summary
- `CHANGELOG.md` - release history and customer-visible changes
- `COMMERCIALIZATION_ROADMAP.md` - commercialization milestones and packaging direction
- `DEVELOPMENT_PROGRESS.md` - ongoing engineering progress log

## Legal and Governance

- `LICENSE` - repository license
- `EULA.md` - end-user license terms
- `DPA.md` - data processing terms
- `SECURITY.md` - security disclosure and reporting policy
- `CLA.md` - contributor license agreement
- `CODE_OF_CONDUCT.md` - community expectations
- `CONTRIBUTING.md` - contribution workflow

## User Documentation

- `docs/getting-started/` - installation and deployment guides
- `docs/user-guide/` - CLI, operations, manual, ProvQL, visualization
- `docs/compliance/` - security and privacy posture

## Developer Documentation

- `docs/developer/` - API reference, schemas, testing, upgrade guidance, release checklist
- `docs/architecture/` - system architecture and provenance model
- `docs/benchmarks/` - performance and benchmark material
- `test/benchmark/optimization_guide.md` - benchmark tuning notes

## Project Process and Templates

- `.github/ISSUE_TEMPLATE/` - issue intake templates
- `.github/PULL_REQUEST_TEMPLATE.md` - PR checklist
- `.claude/plans/` - local planning artifacts, not product documentation

## Current Observations

- `docs/` already has clear topical separation by audience.
- Root-level legal and governance files remain mixed with product docs; this audit provides a stable classifier.
- Planning and progress files are useful for engineering visibility but should not be treated as operator-facing product docs.
- Chinese and English parity exists for several install and manual paths, but not for every developer page.

## Recommended Reading Paths

### New User

1. `README.md`
2. `docs/getting-started/INDEX.md`
3. `docs/user-guide/INDEX.md`

### Operator / SecOps

1. `docs/getting-started/install.md`
2. `docs/user-guide/operations.md`
3. `docs/user-guide/manual.md`

### Contributor / Engineer

1. `CONTRIBUTING.md`
2. `docs/developer/INDEX.md`
3. `docs/architecture/INDEX.md`
4. `DEVELOPMENT_PROGRESS.md`

### Procurement / Legal Review

1. `EULA.md`
2. `DPA.md`
3. `LICENSE`
4. `SECURITY.md`
