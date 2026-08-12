# Open Source Readiness Gap Register

This register tracks remaining capabilities that improve the public open-source release beyond the current release gates.

## Release Blocking

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| CI governance | Authenticated GitHub Actions evidence is not captured in the repository | Release record links to passing CI runs for the final commit |
| Vulnerability scanning | Grype and Trivy evidence is not closed for the current commit | Security has either clean scan outputs or an approved waiver |
| Release approval | Engineering, Security, Legal/project-owner, and Maintainer approvals are not signed | `release-approval-record.md` contains named decisions |
| Final artifacts | Current `dist/` artifacts were generated before the latest commit | Final artifacts, checksums, SBOMs, signatures, and handoff bundle are rebuilt from the release tag |

Current closure progress:

- Release gate collection accepts external GitHub Actions evidence via `--ci-evidence`.
- Grype/Trivy/govulncheck gates accept structured or Markdown waiver evidence via `--waiver`.
- Final artifact generation remains tied to `make release-open-source` from the final release tag.
- Named Engineering, Security, Legal/project-owner, and Maintainer decisions still require real owner signoff.

## Production Operations

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| Secret management | Deployment examples document secrets but do not integrate a concrete secret backend | Kubernetes Secret, Docker env-file, and systemd credential examples are validated |
| TLS automation | TLS is documented but certificate bootstrap and rotation are still operator-driven | Repeatable certificate bootstrap, rotation, and expiry checks exist |
| PostgreSQL operations | Production storage exists, but migration and retention drills need recurring evidence | Schema migration and retention evidence are included in release validation |
| Fleet lifecycle | Agent health is visible, but bulk enrollment, decommission, and certificate rotation workflows need deeper automation | Operators can enroll, rotate, quarantine, and retire agents from one workflow |

Current closure progress:

- Release gate snapshots are available through `make release-gates`, producing Markdown and JSON evidence under `build/`.
- Secret template generation and validation are available through `make ops-secret-template` and `make ops-secret-validate SECRET_ENV=...`.
- Secret backend handoff artifacts for systemd, Docker Compose, and Kubernetes are generated through `make ops-secret-backends SECRET_ENV=...`.
- TLS bootstrap and expiry checking are available through `make ops-tls-bootstrap` and `make ops-tls-check CERTS="..."`.
- PostgreSQL logical backup, optional staging restore, and structured drill reports are available through `make ops-postgres-drill`.
- Local checkpoint backup, restore staging, cutover, and download evidence is gated through `make backup-readiness-gate`.
- Fleet list, lifecycle operations, and dry-run lifecycle plans are wrapped by `scripts/ops/fleet-lifecycle.sh`.
- Constrained VM deployment is guarded by ELF, bpf-tag, SHA-256, service-active, and log-budget checks through `make deploy-vms`.
- Ground-truth dataset export and ATT&CK coverage reporting are available through `make export-ground-truth`.
- Alert quality reporting is available through `make alert-quality ALERTS=...`.
- RBAC and tenant-scope configuration audits are available through `make ops-rbac-audit PROVIDAPT_CONFIG=...`; reports fingerprint API keys instead of writing raw key material.

## Detection and Investigation

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| ATT&CK coverage | Technique guidance and planning exist, but more customer-relevant scenarios need VM evidence | Coverage report maps simulated and detected techniques by tactic and host |
| Ground truth lifecycle | Dataset versioning, split, and hash gates exist; recurring release baselines still need curated ownership | Reproducible datasets can be exported with labels, manifests, and split metadata |
| Provenance UX | Path-only, layout, filtering, and fold controls exist; very large trace ergonomics can still improve | Analysts can collapse, expand, filter, and export large traces without visual clutter |
| Alert quality | Persistent analyst feedback now feeds alert-quality, graph-dataset, detection-quality, and model-closed-loop evidence | Alerts can be marked true positive, false positive, duplicate, or benign with audit trail |

Current closure progress:

- Detection quality reporting merges ATT&CK coverage and analyst alert quality into precision, recall, F1, missed technique, and recommendation evidence through `make detection-quality`.
- ATT&CK coverage planning converts missed techniques into safe simulation, ground-truth, rule assertion, and cleanup tasks through `make attack-coverage-plan`; guidance covers a broader set of common Linux-safe ATT&CK techniques.
- Graph training datasets are generated from normal/attack NDJSON plus ATT&CK ground truth through `make graph-dataset`, producing graph labels, split metadata, and feature schema evidence.
- Dataset version, split support, label balance, and hash inventory are gated through `make dataset-split-gate`.
- GCN, GAT, GraphSAGE, and MLP detector baselines can be trained in the `torch_py39` conda environment through `make graph-train`.
- The end-to-end graph detector training path is wrapped by `make ml-training-pipeline`, which builds graph data, trains a detector, and registers model provenance.
- Dashboard layout now constrains long paths, hashes, hostnames, alert headlines, and action chips to prevent horizontal overflow.
- Provenance summaries expose cluster and high-degree hub views for large investigations.
- Trace Viewer supports path-only focus from a selected node, node-type filtering, file/network folding, and layout modes for tree, compact, timeline, and grouped views.
- Trace SVG layout pressure evidence can be collected against real alerts through `make trace-svg-stress`, including per-layout latency, SVG dimensions, node/edge counts, folded cluster counts, and automatic alert-ID discovery from `/api/v1/control/alerts` when `ALERT_IDS` is omitted.
- Dashboard provenance cluster views now support inspect, focused backward/forward trace links, and filtered cluster JSON export for offline layout and model-training review.
- Alert workflow feedback is persisted to an append-only `alert-feedback.ndjson` ledger, merged back into dashboard alert views after restart, exported through `/api/v1/control/alerts/feedback`, consumed by `make alert-quality ALERT_FEEDBACK=...`, recorded in graph dataset manifests through `make graph-dataset ALERT_FEEDBACK=...`, merged into `make detection-quality`, and accepted by `make model-closed-loop REQUIRE_FEEDBACK=1` from either a feedback file or dataset manifest evidence.
- Three-VM capture/enrichment evidence can be collected over SSH/SCP through `make collect-vm-capture-evidence`, which copies real `providapt-*.ndjson` files and runs `capture-enrichment-field-gate` on the gathered release evidence.

## Enterprise Integration

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| SIEM/SOAR | SIEM mappings exist, but production connectors need environment-specific certification | Splunk, Elastic, and webhook delivery are validated with retry and backpressure evidence |
| RBAC and audit | RBAC exists, but delegated administration needs hardening tests | Tenant-scoped policies, audit export, and role reviews are tested |
| Reporting | Support bundles and scheduled-report plans exist, but customer-specific report delivery needs certification | Scheduled PDF/Markdown/JSON reports summarize fleet risk, alerts, and coverage |
| Upgrade orchestration | Upgrade preflight exists, but fleet-wide staged rollout and rollback need richer automation | Operators can canary, pause, resume, and rollback upgrades across agent groups |

Current closure progress:

- Customer environment certification is aggregated through
  `make customer-env-certification-gate`, covering RBAC delegated admin,
  tenant isolation, audit export, SIEM/SOAR certification, upgrade rollout,
  soak duration, Secret/TLS/PostgreSQL/backup readiness, plugin governance,
  and onboarding checks.
- Customer environment certification validates audit export structure and role
  review content, not only file presence: audit exports need records, and role
  reviews need approved named-owner entries with no pending placeholders.
- Enterprise readiness reporting aggregates release gates, secret backend handoff, PostgreSQL drill status, SIEM/SOAR delivery checks, upgrade rollout evidence, and detection quality through `make enterprise-readiness`.
- Enterprise readiness now also consumes RBAC audit and scheduled report plan evidence when `RBAC_AUDIT_JSON` and `REPORT_PLAN_JSON` are supplied.
- Policy approval readiness gates RBAC status, tenant scoping, approval workflow, required approval actions, and approval audit evidence through `make policy-approval-gate`.
- Support bundle readiness gates archive presence, redaction, export audit, and download evidence through `make support-bundle-gate`.
- Runtime deployment diagnostics gates API auth, TLS, storage encryption, policy sync, kernel attach, control plane, and support bundle availability through `make deployment-diagnostics-gate`.
- VM fleet deployment verification captures dashboard, graph export, alert workflow, fleet health, version, and report-age evidence through `make verify-vm-fleet`.
- Open-source development backlog generation is available through `make open-source-development-backlog`, with `LOCAL_ONLY=1` and `PHASE=...` filters for step-by-step local implementation planning.
- Scheduled executive/compliance report delivery plans are generated through `make scheduled-report-plan`.
- Upgrade rollout planning produces canary, wave, pause/resume, rollback, and
  optional agent-group batch evidence through `make upgrade-rollout-plan
  BATCH_BY_GROUP=1`.
- SIEM verification remains available through `make ops-siem-verify`; environment certification still requires customer SIEM/SOAR endpoints.

## Scale and Ecosystem

| Area | Gap | Expected Outcome |
| --- | --- | --- |
| Performance certification | Benchmarks exist, but long-duration noisy-host soak evidence should be expanded | 24-72 hour soak results define throughput, loss, CPU, memory, and disk budgets |
| Plugin ecosystem | Plugin development docs exist, but signed plugin distribution and compatibility policy need productization | Plugins have signing, version compatibility, and safe rollback rules |
| Model training | Simulation logs can train detectors; broader model promotion automation can still mature | Model versions, feature schemas, training provenance, and drift reports are tracked and enforced before deployment |
| Customer onboarding | Handoff docs exist, but guided first-run setup can be smoother | A guided setup wizard validates prerequisites and generates a ready-to-run config |

Current closure progress:

- Soak readiness reporting evaluates long-duration samples against duration, CPU, memory, disk, and dropped-event budgets through `make soak-readiness`.
- Long-duration soak samples can be appended from a status endpoint or captured JSON through `make soak-sample`.
- Model registry, dataset drift, feature-schema compatibility, and deployable model artifact SHA-256 checks are available for training provenance.
- Model lifecycle promotion is gated through `make model-lifecycle-gate`,
  requiring closed-loop readiness, deploy-gate pass status, stable drift
  evidence, sufficient analyst feedback/reviewed labels, required feedback-label
  diversity, a minimum baseline window, matching model identity/version/feature
  schema evidence, optional named owner approval, and an archive-ready promotion
  packet readiness summary.
- First-run onboarding bundles generate a starter config, checklist,
  Tailscale/SSH/API/TLS/secrets/PostgreSQL environment checks, a fill-in check
  result template, prioritized next actions, and manifest through
  `make onboarding-wizard`; optional `CHECK_RESULTS=...` merges observed
  pass/warn/fail results into `onboarding-report.md` for handoff evidence.
- Plugin release gating validates plugin manifests, semantic versions,
  supported plugin types, least-privilege permission declarations,
  compatibility ranges, signed distribution metadata, signature evidence, and
  concrete rollback instructions through `make plugin-release-gate`.
- Plugin catalog gating aggregates multiple plugin release-gate outputs through
  `make plugin-catalog-gate`, blocking duplicate plugin identities, unsigned
  entries, missing permissions, incomplete distribution metadata, and missing
  rollback evidence.
- Visual regression gating now requires captured Dashboard and Trace Viewer
  screenshots, hashes, and passing DOM assertions for each required viewport;
  dry-run planning must explicitly opt out through `ALLOW_PLANNED_VISUALS=1`.
  Snapshot evidence now includes baseline comparison summaries for changed,
  new, skipped, and missing-baseline review.
- Open-source readiness gating now aggregates release gate status, operations
  readiness, enterprise readiness, model lifecycle promotion packets, visual
  browser baseline coverage, onboarding outputs, plugin release gates, required
  documentation, and approval evidence into one local milestone report.
- Open-source milestone packaging is available through
  `make open-source-milestone`, combining readiness, readiness backlog,
  development backlog, release gate status, release evidence consistency, model
  lifecycle promotion readiness, and visual baseline evidence into one
  JSON/Markdown local milestone package.
- Model deployment gating blocks unregistered, schema-incompatible, missing-artifact, artifact-hash-mismatched, drift-required, or low precision/recall detector versions through `make model-deploy-gate`.
- Runtime online ML loading can require `model-deploy-gate.json` evidence before enabling scorer deployment.
