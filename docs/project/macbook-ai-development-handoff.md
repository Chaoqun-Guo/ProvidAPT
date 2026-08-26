# MacBook AI Development Handoff

This document is for continuing ProvidAPT development on a MacBook with Codex,
Claude, or another coding agent.

## Snapshot

- Repository: `ProvidAPT`
- Handoff commit: `65a6f25 fix: stabilize trace svg legend and clusters`
- Portable archive: `ProvidAPT-macbook-dev-65a6f25.tar.gz`
- Archive checksum file: `ProvidAPT-macbook-dev-65a6f25.tar.gz.sha256`
- VM state at handoff: `vm-ubuntu-slave`, `vm-centos-slave`, and
  `vm-ubuntu-master` were cleaned, ProvidAPT services were stopped, and shutdown
  commands were issued.

## MacBook Setup

1. Copy the archive and checksum file to the MacBook.
2. Verify the archive:

   ```bash
   shasum -a 256 ProvidAPT-macbook-dev-65a6f25.tar.gz
   cat ProvidAPT-macbook-dev-65a6f25.tar.gz.sha256
   ```

3. Extract the source tree:

   ```bash
   tar -xzf ProvidAPT-macbook-dev-65a6f25.tar.gz
   cd ProvidAPT
   ```

4. Install expected local tools:

   ```bash
   brew install go make git docker jq
   ```

5. Recommended Go environment:

   ```bash
   export GOTELEMETRY=off
   export GOCACHE="$PWD/.tmp-gocache"
   ```

## Current Functional State

### Control Plane Dashboard

- Main dashboard route: `/dashboard`
- Dashboard shell template: `pkg/api/templates/dashboard_shell.html`
- Dashboard metrics template: `pkg/api/templates/dashboard_metrics.html`
- Dashboard panel template wrapper: `pkg/api/templates/dashboard_panels.html`
- Dashboard panel modules: `pkg/api/templates/panels/*.html`
- Dashboard primary CSS: `pkg/api/static/dashboard.css`
- Dashboard responsive CSS: `pkg/api/static/dashboard-responsive.css`
- Dashboard JS: `pkg/api/static/dashboard.js`
- Trace Viewer CSS: `pkg/api/static/trace-viewer.css`
- Trace Viewer JS: `pkg/api/static/trace-viewer.js`
- Recent fixes:
  - Uniform button sizing and visual hierarchy.
  - Compact `Operations Summary`.
  - Improved `Evaluation Ground Truth`, `Delivery Health`, and `Support Bundle`
    panel layouts.
  - Restored draggable panel resizing and preserved resize handle behavior.

### Trace SVG and Trace Viewer

- Raw SVG export: `/api/v1/alerts/<id>/svg`
- Interactive viewer: `/api/v1/alerts/<id>/svg/view`
- Main implementation: `pkg/api/svg.go`
- Routing implementation: `pkg/api/api.go`
- Tests: `pkg/api/api_test.go`
- Current behavior:
  - Raw SVG remains export-friendly.
  - Viewer provides zoom, fit width, search highlighting, cross-link toggle,
    node type filtering, file/network fold controls, cluster highlight, raw SVG
    open, SVG/PNG export, JSON/Markdown report links, and Markdown
    investigation snippet copy.
  - Nodes, edges, and clusters expose clickable detail metadata in the viewer
    side panel, including source/target, relation, event summary, identity,
    depth, and folded member details.
  - Layout modes are available for tree, compact, timeline, and grouped views.
    Raw SVG export accepts `?layout=tree|compact|timeline|grouped`.
  - Cluster boxes summarize folded nodes with `data-folded-count`,
    `data-members`, `data-reason`, depth, and node type metadata.
  - Legend is vertical and avoids overlap with the graph.
  - Cluster placement is depth-column based to avoid cross-column overflow.
  - Visual regression screenshot capture is available through
    `make visual-regression-snapshots` for dashboard and Trace Viewer evidence,
    and `make visual-regression-gate` gates captured screenshots/baselines.
  - Dashboard captures include DOM overflow assertions for horizontal document
    overflow, element bounds, and text overflow at `390x844`, `1366x768`,
    `1920x1080`, and `2560x1080`.
  - Trace Viewer captures include browser DOM assertions for rendered SVG,
    layout modes, PNG/SVG/raw export controls, and report links across the same
    viewport set.
  - Dashboard HTML, primary CSS, responsive CSS, and JS are split into embedded
    static assets served from `/dashboard`, `/assets/dashboard.css`,
    `/assets/dashboard-responsive.css`, and `/assets/dashboard.js`.
  - Trace Viewer CSS and JS are split into embedded static assets served from
    `/assets/trace-viewer.css` and `/assets/trace-viewer.js`.

### Capture, Enrichment, and ML Pipeline

- Event field source documentation: `docs/developer/event-field-source.md`
- Evaluation guide: `docs/getting-started/evaluation.md`
- Training script entry: `scripts/evaluation/train_graph_detector.py`
- Previous GPU training server used by the project:
  - Host: `guocq@guocq-cslab`
  - Conda env: `torch_py310`
- Do not assume VM-collected training data is present in this archive unless it
  is explicitly copied separately. Generated datasets and large `.ndjson` files
  should stay out of source archives.

## Validation Commands

Run focused checks first:

```bash
export GOTELEMETRY=off
export GOCACHE="$PWD/.tmp-gocache"
go test -count=1 ./pkg/api
```

Run broader Go tests when the local environment is ready:

```bash
go test -count=1 ./...
```

Build a Linux agent binary from macOS:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags bpf \
  -o build/bin/providaptd-linux-amd64 ./cmd/agent/daemon
```

Build a local macOS binary for non-eBPF/control-plane development:

```bash
go build -o build/bin/providaptd-darwin ./cmd/agent/daemon
```

## VM Deployment Notes

Current test VMs are reachable through Tailscale MagicDNS. Prefer domain names
for deployment, verification, telemetry, and policy endpoints. Keep the real
tailnet suffix and VM passwords in local secret storage; do not commit them.

| Role                  | Address                                 | User     | Password |
| --------------------- | --------------------------------------- | -------- | -------- |
| Ubuntu agent          | `vm-ubuntu-slave.<TAILSCALE_DOMAIN>`    | `ubuntu` | local secret |
| CentOS agent          | `vm-centos-slave.<TAILSCALE_DOMAIN>`    | `centos` | local secret |
| Ubuntu control/server | `vm-ubuntu-master.<TAILSCALE_DOMAIN>`   | `ubuntu` | local secret |

Service path on VMs:

```bash
/usr/local/sbin/providaptd
systemctl status providapt.service
```

Deployment pattern:

```bash
scp build/bin/providaptd-linux-amd64 user@host:/tmp/providaptd
ssh user@host 'sudo install -m 0755 /tmp/providaptd /usr/local/sbin/providaptd && sudo systemctl restart providapt.service'
```

Agent configs should point to the control-plane domain instead of any legacy
private IP address:

```yaml
telemetry:
  endpoint: "vm-ubuntu-master.<TAILSCALE_DOMAIN>:50051"
policy:
  endpoint: "http://vm-ubuntu-master.<TAILSCALE_DOMAIN>:18080"
```

Validate a copied config before deployment:

```bash
make verify-vm-config PROVIDAPT_CONFIG=/path/to/providapt.toml \
  VM_CONTROL_HOST=vm-ubuntu-master.<TAILSCALE_DOMAIN>
```

The control plane is verified on:

```text
http://vm-ubuntu-master.<TAILSCALE_DOMAIN>:18080/dashboard
```

## Important Repository Hygiene

- Do not commit generated training data, `.ndjson`, `.jsonl`, screenshots, or
  `build/bin` binaries.
- Keep large datasets outside the repository and document their path in a local
  run manifest.
- Clean local generated files before handoff:

  ```bash
  rm -rf .tmp-* build/bin
  find build -type f \( -name "*.ndjson" -o -name "*.jsonl" -o -name "*.png" \) -delete
  ```

- Archive source with `git archive` when possible:

  ```bash
  git archive --format=tar.gz --prefix=ProvidAPT/ -o ProvidAPT-macbook-dev-$(git rev-parse --short HEAD).tar.gz HEAD
  ```

## Recommended Next Work

### Traceability UX

- Large-trace filtering and file/network fold controls are available in the
  Trace Viewer; path-only focus from a selected node is available. Continue
  refining very large trace ergonomics and baseline visual regression coverage.
- Keep visual regression baselines current for dashboard and Trace Viewer
  exports; Dashboard screenshot manifests now include DOM overflow assertions.

### Dashboard UX

- Continue reviewing every module panel for overflow at mobile `390x844`,
  `1366x768`, `1920x1080`, and ultrawide `2560x1080` resolutions.
- Dashboard CSS and JavaScript are now split out of the HTML shell into
  embedded static assets; continue moving repeated markup toward structured
  templates if the panel count grows further.

### Detection and ML

- Ensure capture/enrichment reliably records `cmdline`, `exe_path`, `pathname`,
  UID/GID, PID/PPID, network tuple, and event type. Use
  `make capture-enrichment-field-gate EVENTS=...` to produce JSON/Markdown
  coverage evidence from VM or evaluation NDJSON.
- Use `make collect-vm-capture-evidence PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave"`
  to collect real three-VM NDJSON release evidence over SSH/SCP and run the
  capture/enrichment field gate on the gathered files.
- Keep benign and attack datasets separated with explicit manifests.
- Dataset versioning, split support, label balance, and output hash inventory
  can be gated with `make dataset-split-gate DATASET_MANIFEST=...`.
- Online detector alerts include model identity/version and feature-count
  metadata.
- Online detector loading can require `model-deploy-gate.json` evidence through
  `analyzer.require_ml_deploy_gate` or
  `PROVIDAPT_ANALYZER_REQUIRE_ML_DEPLOY_GATE`; the scorer validates
  `providapt.model_deploy_gate.v1`, pass status, and model identity/version
  before enabling runtime scoring.
- Analyst TP/FP feedback is persisted to `alert-feedback.ndjson`, exportable via
  `/api/v1/control/alerts/feedback`, and consumable by alert-quality,
  graph-dataset, detection-quality, and model-closed-loop evaluation reports.
  `model-closed-loop REQUIRE_FEEDBACK=1` now requires at least one reviewed
  feedback label (`true_positive`, `false_positive`, `benign`, or `duplicate`).
- Model promotion can be gated with `make model-lifecycle-gate`, which combines
  closed-loop readiness, deploy-gate pass status, stable drift evidence,
  minimum feedback/reviewed-label volume, baseline duration, and named owner
  approval evidence.

### Open Source Readiness

- ProvidAPT is now an open-source distribution: paid-edition UI/API entry points should remain removed.
- Artifact signing has an explicit release gate:
  `make artifact-signing-gate REQUIRED_ARTIFACTS="archive deb rpm helm monitoring"`.
  The operator-release gate consumes this evidence through its
  `artifact_signing` section.
- RBAC, audit, multi-tenant scope, and policy approval workflow have an
  explicit `make policy-approval-gate` evidence check.
- Operator-environment certification can be aggregated with
  `make operator-env-certification-gate` for delegated admin, tenant isolation,
  audit export, SIEM/SOAR certification, staged upgrade controls, 24-hour soak,
  TLS/state backend/backup evidence, plugin governance, and onboarding checks.
- Backup/restore/cutover evidence has `make backup-readiness-gate`.
- Support bundle redaction/audit evidence has `make support-bundle-gate`.
- Runtime deployment diagnostics evidence has `make deployment-diagnostics-gate`.
- Operations readiness consumes policy approval, backup, support bundle, and
  deployment diagnostics gate outputs.
- Formal public-release closure now requires current-commit GitHub Actions
  evidence archived with `RELEASE_EVIDENCE=...`, current-commit security scan
  manifests, final tag artifacts/checksums/SBOMs/signatures, and named
  Product/Security/Legal/Support/Maintainer approvals. The local gates
  enforce the evidence; they do not replace real owner signatures.

## Useful Documentation Entry Points

- Project layout: `docs/project/project-layout.md`
- Production readiness: `docs/project/production-readiness.md`
- User manual: `docs/user-guide/manual.md`
- Visual guide: `docs/user-guide/visual-guide.md`
- Dashboard API: `docs/developer/dashboard-api.md`
- API reference: `docs/developer/api-reference.md`
- Data schema: `docs/developer/data-schema.md`
- Event field source: `docs/developer/event-field-source.md`
- Architecture overview: `docs/architecture/overview.md`

## Agent Instructions for Continuation

When continuing on MacBook:

1. Start from `git status --short` and `git log -5 --oneline`.
2. Read the files relevant to the requested module before editing.
3. Prefer minimal root-cause fixes over broad rewrites.
4. Run the most focused test first, then broader tests.
5. Do not commit or push unless explicitly requested.
6. Do not include generated data or VM logs in commits.
7. For dashboard changes, verify with browser screenshots if possible.
8. For trace SVG changes, validate both `/svg` and `/svg/view`.
