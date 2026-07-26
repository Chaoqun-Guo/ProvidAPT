# Commercial Feature Gap Register

This register tracks remaining product capabilities that improve commercial readiness beyond the current release gates.

## P0 - Release Blocking

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| CI governance | Authenticated GitHub Actions evidence is not captured in the repository | Release record links to passing CI runs for the final commit |
| Vulnerability scanning | Grype and Trivy evidence is not closed for the current commit | Security has either clean scan outputs or an approved waiver |
| External approval | Product, Security, Legal, Support, and Sales Engineering approvals are not signed | `commercial-approval-record.md` contains named decisions |
| Final artifacts | Current `dist/` artifacts were generated before the latest commit | Final artifacts, checksums, SBOMs, signatures, and handoff bundle are rebuilt from the release tag |

## P1 - Production Operations

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| Secret management | Deployment examples document secrets but do not integrate a concrete secret backend | Kubernetes Secret, Docker env-file, and systemd credential examples are validated |
| TLS automation | TLS is documented but certificate bootstrap and rotation are still operator-driven | Repeatable certificate bootstrap, rotation, and expiry checks exist |
| PostgreSQL operations | Production storage exists, but backup, restore, migration, and retention drills need recurring evidence | Restore drill and schema migration evidence are included in release validation |
| Fleet lifecycle | Agent health is visible, but bulk enrollment, decommission, and certificate rotation workflows need deeper automation | Operators can enroll, rotate, quarantine, and retire agents from one workflow |

Current closure progress:

- Secret template generation is available through `make ops-secret-template`.
- TLS expiry checking is available through `make ops-tls-check CERTS="..."`.
- PostgreSQL logical backup and optional staging restore drills are available through `make ops-postgres-drill`.
- Fleet list and lifecycle operations are wrapped by `scripts/ops/fleet-lifecycle.sh`.
- Ground-truth dataset export and ATT&CK coverage reporting are available through `make export-ground-truth`.

## P2 - Detection and Investigation

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| ATT&CK coverage | Full-chain simulation exists, but technique coverage is still limited to a curated safe subset | Coverage report maps simulated and detected techniques by tactic and host |
| Ground truth lifecycle | Ground truth is captured, but dataset versioning and training/test splits need formal tooling | Reproducible datasets can be exported with labels, manifests, and split metadata |
| Provenance UX | Graphs support tree and horizontal layouts, but large investigations need stronger clustering and summarization | Analysts can collapse, expand, filter, and export large traces without visual clutter |
| Alert quality | Alerts are visible, but precision/recall tracking needs closed-loop analyst feedback | Alerts can be marked true positive, false positive, duplicate, or benign with audit trail |

## P3 - Enterprise Integration

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| SIEM/SOAR | SIEM mappings exist, but production connectors need environment-specific certification | Splunk, Elastic, and webhook delivery are validated with retry and backpressure evidence |
| RBAC and audit | RBAC exists, but multi-tenant boundaries and delegated administration need hardening tests | Tenant-scoped policies, audit export, and role reviews are tested |
| Reporting | Support bundles exist, but executive and compliance reports need scheduled generation | Scheduled PDF/Markdown/JSON reports summarize fleet risk, alerts, and coverage |
| Upgrade orchestration | Upgrade preflight exists, but fleet-wide staged rollout and rollback need richer automation | Operators can canary, pause, resume, and rollback upgrades across agent groups |

## P4 - Scale and Ecosystem

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| Performance certification | Benchmarks exist, but long-duration noisy-host soak evidence should be expanded | 24-72 hour soak results define throughput, loss, CPU, memory, and disk budgets |
| Plugin ecosystem | Plugin development docs exist, but signed plugin distribution and compatibility policy need productization | Plugins have signing, version compatibility, and safe rollback rules |
| Model training | Simulation logs can train detectors, but model registry and drift monitoring are not yet formalized | Model versions, feature schemas, training provenance, and drift reports are tracked |
| Customer onboarding | Handoff docs exist, but guided first-run setup can be smoother | A guided setup wizard validates prerequisites and generates a ready-to-run config |
