# Helm Deployment

This guide describes Helm-based installation, upgrade, rollback, and uninstall workflows.

## Prerequisites

- Kubernetes cluster with Linux nodes.
- Node permissions required for eBPF capture are approved by the cluster owner.
- Helm 3.
- PostgreSQL or a managed PostgreSQL-compatible service for production control-plane state.

## Install

```bash
helm install providapt ./dist/providapt-helm-v<version>.tgz \
  --namespace providapt \
  --create-namespace \
  --values examples/helm/values-production.yaml
```

## Upgrade

```bash
helm upgrade providapt ./dist/providapt-helm-v<version>.tgz \
  --namespace providapt \
  --values examples/helm/values-production.yaml
```

## Rollback

```bash
helm history providapt --namespace providapt
helm rollback providapt <revision> --namespace providapt
```

## Uninstall

```bash
helm uninstall providapt --namespace providapt
```

Delete persistent volumes only after backup and operator approval.

## Production Values

Required production values:

- image repository and immutable tag or digest
- dashboard/API reachability restricted by network policy, TLS, or trusted-header SSO
- TLS enabled
- PostgreSQL DSN or external secret reference
- fleet enrollment policy
- SIEM endpoint and token secret
- resource requests and limits
- node selectors or tolerations for capture agents

## Validation

```bash
kubectl get pods -n providapt
kubectl logs -n providapt deploy/providapt --tail=100
kubectl port-forward -n providapt svc/providapt 18080:18080
curl -s http://localhost:18080/api/v1/status
```

## Security Notes

- Keep privileged DaemonSet permissions limited to agent pods that require host capture.
- Store TLS keys, SIEM tokens, and database credentials in Kubernetes secrets or an external secret manager.
- Review hostPath mounts with the cluster security team.
- Use network policies to restrict dashboard, gRPC, PostgreSQL, and metrics access.
