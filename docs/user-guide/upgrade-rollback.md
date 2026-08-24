# Upgrade and Rollback

This guide is for operators applying a new ProvidAPT package, container image, or Helm chart.

## Preflight

```bash
providaptctl -config-check -config /etc/providapt/providapt.toml
sudo scripts/upgrade/preflight-linux.sh /path/to/providapt.tar.gz
```

Required checks:

- release artifact checksum matches the approved `checksums.txt`
- signature verification passes
- backup exists
- disk space is sufficient
- current service state is captured
- rollback artifact is available

## Package Upgrade

Debian:

```bash
sudo apt install ./providapt_<version>_amd64.deb
sudo systemctl restart providapt.service
```

RPM:

```bash
sudo rpm -Uvh ./providapt-<version>.x86_64.rpm
sudo systemctl restart providapt.service
```

## Helm Upgrade

```bash
helm upgrade providapt ./dist/providapt-helm-v<version>.tgz \
  --namespace providapt \
  --values examples/helm/values-production.yaml
```

## Post-Upgrade Validation

```bash
providaptctl -status
curl -s http://<server>:18080/api/v1/status
curl -s http://<server>:18080/api/v1/control/fleet
curl -s http://<server>:18080/api/v1/control/upgrade
```

Validate:

- dashboard loads
- fleet report ages are fresh
- policy state is not stale
- alerts and traces still load
- SIEM delivery is not backing up unexpectedly

## Rollback

Package rollback:

```bash
sudo systemctl stop providapt.service
sudo rpm -Uvh --oldpackage ./providapt-<previous>.x86_64.rpm
sudo systemctl start providapt.service
```

Helm rollback:

```bash
helm history providapt --namespace providapt
helm rollback providapt <revision> --namespace providapt
```

## Rollback Decision Points

Rollback when:

- the daemon cannot start after upgrade
- PostgreSQL or local store migration fails
- fleet visibility is lost
- alert workflow or policy distribution is blocked
- performance exceeds approved thresholds

Document the rollback in the audit log and operator incident record.
