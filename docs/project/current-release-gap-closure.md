# Current Release Gap Closure Plan

Date: 2026-07-22
Branch: master

## Completed in this pass

- Event detail drill-down is available from dashboard event cards.
- Alert Workflow includes an inline related-event search action.
- Production and packaged sample configs include bounded NDJSON retention values.
- Production config documents a small-disk command allow-list profile.
- Repeatable VM deployment helper removes old NDJSON files during rollout.
- Storage-budget helper reports NDJSON, store, support bundle, backup, compliance, and SIEM outbox usage.
- SIEM documentation maps normalized event fields to Splunk and Elastic/ECS-style fields.

## External release gates still required

- GitHub Actions status confirmation requires authenticated `gh` or GitHub UI access.
- Grype/Trivy scan closure requires a networked or pre-approved scanner environment.
- Security, Legal, and Support approvals must be signed by named owners.
- Final versioned artifacts, checksums, SBOM, signatures, and handoff bundle must be regenerated for the final release tag.

## Operator validation commands

```bash
go test ./pkg/api ./pkg/config ./internal/storage/format
PROVIDAPT_VM_HOSTS="ubuntu@192.168.150.129 centos@192.168.150.131 ubuntu@192.168.150.132" \
  bash scripts/deploy/deploy-vms.sh
bash scripts/deploy/check-storage-budget.sh /var/log/providapt
```
