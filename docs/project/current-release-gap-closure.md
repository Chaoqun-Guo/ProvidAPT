# Current Release Gap Closure Plan

Date: 2026-07-26
Branch: master
Verification commit: `9cdf515e88d7ed28eeaa429a3cd7d7e0354673ad`

## Completed in this pass

- Release-scoped Go validation passed on the current workspace for `pkg/api`, `pkg/config`, `internal/storage/format`, `pkg/releasecheck`, `pkg/controlplaneha`, `cmd/cli/providaptctl`, and `cmd/cli/providapt-sign`.
- GitHub Actions status was checked locally, but `gh` is not authenticated in this environment.
- Local scanner availability was checked. `govulncheck`, `grype`, and `trivy` are not installed on the workstation.
- Docker daemon access was confirmed, but running third-party scanner containers requires explicit approval because it mounts the repository into external container images and may pull images from the network.
- Event detail drill-down is available from dashboard event cards.
- Alert Workflow includes an inline related-event search action.
- Production and packaged sample configs include bounded NDJSON retention values.
- Production config documents a small-disk command allow-list profile.
- Repeatable VM deployment helper removes old NDJSON files during rollout.
- Storage-budget helper reports NDJSON, store, support bundle, backup, compliance, and SIEM outbox usage.
- SIEM documentation maps normalized event fields to Splunk and Elastic/ECS-style fields.
- Alert Workflow dashboard exposes analyst quality counters and browser-side quality export.
- Model registry and dataset drift helpers record training provenance and compare candidate datasets by split, tactic, and technique.
- Investigation Console graph summaries now surface provenance clusters and high-degree hubs for large traces.
- Model registry records and validates the production feature schema hash before model registration.

## External release gates still required

- GitHub Actions status confirmation requires authenticated `gh` or GitHub UI access.
- Grype/Trivy scan closure requires locally installed scanners or explicit approval to run approved container images against the repository.
- Security, Legal, and Support approvals must be signed by named owners.
- Final versioned artifacts, checksums, SBOM, signatures, and handoff bundle must be regenerated for the final release tag.

## Operator validation commands

```bash
go test ./pkg/api ./pkg/config ./internal/storage/format
PROVIDAPT_VM_HOSTS="ubuntu@192.168.150.129 centos@192.168.150.131 ubuntu@192.168.150.132" \
  bash scripts/deploy/deploy-vms.sh
bash scripts/deploy/check-storage-budget.sh /var/log/providapt
```
