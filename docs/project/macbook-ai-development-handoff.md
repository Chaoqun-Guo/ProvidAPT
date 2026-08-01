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
- Dashboard HTML implementation: `pkg/api/dashboard.html`
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
    cluster highlight, raw SVG open, and download.
  - Cluster boxes summarize folded nodes with `data-folded-count`,
    `data-members`, `data-reason`, depth, and node type metadata.
  - Legend is vertical and avoids overlap with the graph.
  - Cluster placement is depth-column based to avoid cross-column overflow.

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

- Add node click-to-detail inside Trace Viewer.
- Add edge click-to-event-detail with source, target, relation, timestamp, path,
  command line, and enrichment fields.
- Add layout modes: tree, compact tree, timeline, and grouped-by-process.
- Add export options for `PNG`, `SVG`, and investigation report snippets.

### Dashboard UX

- Continue reviewing every module panel for overflow at `1366x768`,
  `1920x1080`, and ultrawide resolutions.
- Add visual regression screenshots for dashboard and Trace Viewer.
- Convert large inline dashboard HTML into structured templates or static assets
  when feasible.

### Detection and ML

- Ensure capture/enrichment reliably records `cmdline`, `exe_path`, `pathname`,
  UID/GID, PID/PPID, network tuple, and event type.
- Keep benign and attack datasets separated with explicit manifests.
- Add model version metadata to online detector outputs.
- Add online feedback loop from analyst TP/FP labels back into evaluation data.

### Commercial Readiness

- Harden activation server integration and upgrade artifact signing.
- Continue RBAC, audit, multi-tenant boundaries, and policy approval workflow.
- Expand operational readiness gates for backup, SIEM, support bundle, and
  deployment diagnostics.

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
