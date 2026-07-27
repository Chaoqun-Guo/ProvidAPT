# Commercial Feature Gap Register

This register tracks remaining product capabilities that improve commercial readiness beyond the current release gates.

## P0 - Release Blocking

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| CI governance | Authenticated GitHub Actions evidence is not captured in the repository | Release record links to passing CI runs for the final commit |
| Vulnerability scanning | Grype and Trivy evidence is not closed for the current commit | Security has either clean scan outputs or an approved waiver |
| External approval | Product, Security, Legal, Support, and Sales Engineering approvals are not signed | `commercial-approval-record.md` contains named decisions |
| Final artifacts | Current `dist/` artifacts were generated before the latest commit | Final artifacts, checksums, SBOMs, signatures, and handoff bundle are rebuilt from the release tag |

Current closure progress:

- Release gate collection accepts external GitHub Actions evidence via `--ci-evidence`.
- Grype/Trivy/govulncheck gates accept structured or Markdown waiver evidence via `--waiver`.
- Final artifact generation remains tied to `make release-commercial` from the final release tag.
- Named Product, Security, Legal, Support, and Sales Engineering decisions still require real owner signoff.

## P1 - Production Operations

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| Secret management | Deployment examples document secrets but do not integrate a concrete secret backend | Kubernetes Secret, Docker env-file, and systemd credential examples are validated |
| TLS automation | TLS is documented but certificate bootstrap and rotation are still operator-driven | Repeatable certificate bootstrap, rotation, and expiry checks exist |
| PostgreSQL operations | Production storage exists, but backup, restore, migration, and retention drills need recurring evidence | Restore drill and schema migration evidence are included in release validation |
| Fleet lifecycle | Agent health is visible, but bulk enrollment, decommission, and certificate rotation workflows need deeper automation | Operators can enroll, rotate, quarantine, and retire agents from one workflow |

Current closure progress:

- Release gate snapshots are available through `make release-gates`, producing Markdown and JSON evidence under `build/`.
- Secret template generation and validation are available through `make ops-secret-template` and `make ops-secret-validate SECRET_ENV=...`.
- Secret backend handoff artifacts for systemd, Docker Compose, and Kubernetes are generated through `make ops-secret-backends SECRET_ENV=...`.
- TLS bootstrap and expiry checking are available through `make ops-tls-bootstrap` and `make ops-tls-check CERTS="..."`.
- PostgreSQL logical backup, optional staging restore, and structured drill reports are available through `make ops-postgres-drill`.
- Fleet list, lifecycle operations, and dry-run lifecycle plans are wrapped by `scripts/ops/fleet-lifecycle.sh`.
- Ground-truth dataset export and ATT&CK coverage reporting are available through `make export-ground-truth`.
- Alert quality reporting is available through `make alert-quality ALERTS=...`.
- RBAC and tenant-scope configuration audits are available through `make ops-rbac-audit PROVIDAPT_CONFIG=...`.

## P2 - Detection and Investigation

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| ATT&CK coverage | Full-chain simulation exists, but technique coverage is still limited to a curated safe subset | Coverage report maps simulated and detected techniques by tactic and host |
| Ground truth lifecycle | Ground truth is captured, but dataset versioning and training/test splits need formal tooling | Reproducible datasets can be exported with labels, manifests, and split metadata |
| Provenance UX | Graphs support tree and horizontal layouts, and dashboard summaries now group clusters and hubs; full in-canvas expand/collapse still needs richer layout controls | Analysts can collapse, expand, filter, and export large traces without visual clutter |
| Alert quality | Alerts are visible, but precision/recall tracking needs closed-loop analyst feedback | Alerts can be marked true positive, false positive, duplicate, or benign with audit trail |

Current closure progress:

- Detection quality reporting merges ATT&CK coverage and analyst alert quality into precision, recall, F1, missed technique, and recommendation evidence through `make detection-quality`.
- ATT&CK coverage planning converts missed techniques into safe simulation, ground-truth, rule assertion, and cleanup tasks through `make attack-coverage-plan`.
- Dashboard layout now constrains long paths, hashes, hostnames, alert headlines, and action chips to prevent horizontal overflow.
- Provenance summaries expose cluster and high-degree hub views for large investigations.

## P3 - Enterprise Integration

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| SIEM/SOAR | SIEM mappings exist, but production connectors need environment-specific certification | Splunk, Elastic, and webhook delivery are validated with retry and backpressure evidence |
| RBAC and audit | RBAC exists, but multi-tenant boundaries and delegated administration need hardening tests | Tenant-scoped policies, audit export, and role reviews are tested |
| Reporting | Support bundles exist, but executive and compliance reports need scheduled generation | Scheduled PDF/Markdown/JSON reports summarize fleet risk, alerts, and coverage |
| Upgrade orchestration | Upgrade preflight exists, but fleet-wide staged rollout and rollback need richer automation | Operators can canary, pause, resume, and rollback upgrades across agent groups |

Current closure progress:

- Enterprise readiness reporting aggregates release gates, secret backend handoff, PostgreSQL drill status, and detection quality through `make enterprise-readiness`.
- Enterprise readiness now also consumes RBAC audit and scheduled report plan evidence when `RBAC_AUDIT_JSON` and `REPORT_PLAN_JSON` are supplied.
- Scheduled executive/compliance report delivery plans are generated through `make scheduled-report-plan`.
- Upgrade rollout planning produces canary, wave, pause/resume, and rollback evidence through `make upgrade-rollout-plan`.
- SIEM verification remains available through `make ops-siem-verify`; environment certification still requires customer SIEM/SOAR endpoints.

## P4 - Scale and Ecosystem

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| Performance certification | Benchmarks exist, but long-duration noisy-host soak evidence should be expanded | 24-72 hour soak results define throughput, loss, CPU, memory, and disk budgets |
| Plugin ecosystem | Plugin development docs exist, but signed plugin distribution and compatibility policy need productization | Plugins have signing, version compatibility, and safe rollback rules |
| Model training | Simulation logs can train detectors, and registry, drift, and feature-schema compatibility checks now exist; runtime model deployment gating still needs integration | Model versions, feature schemas, training provenance, and drift reports are tracked and enforced before deployment |
| Customer onboarding | Handoff docs exist, but guided first-run setup can be smoother | A guided setup wizard validates prerequisites and generates a ready-to-run config |

Current closure progress:

- Soak readiness reporting evaluates long-duration samples against duration, CPU, memory, disk, and dropped-event budgets through `make soak-readiness`.
- Model registry, dataset drift, and feature-schema compatibility gates are available for training provenance.
- First-run onboarding bundles generate a starter config, checklist, and manifest through `make onboarding-wizard`.
- Plugin release gating validates plugin manifests, semantic versions, supported plugin types, signature evidence, and rollback instructions through `make plugin-release-gate`.
- Model deployment gating blocks unregistered, schema-incompatible, drift-required, or low precision/recall detector versions through `make model-deploy-gate`.
