# Secret Management

ProvidAPT production deployments should inject secrets through the operator's
approved secret manager or deployment pipeline. Do not commit filled secret
files to source control or include them in support bundles.

## Generate the Contract

```bash
make ops-secret-template
```

This writes `build/providapt.secrets.env.example`, a placeholder contract that
lists the environment variables expected by production integrations.

## Validate a Filled Env-File

```bash
make ops-secret-validate SECRET_ENV=/secure/path/providapt.secrets.env
```

The validator checks file permissions, required variables, placeholder values,
minimum secret length, and PostgreSQL DSN password presence.
On Linux production hosts, enforce secret file modes with:

```bash
STRICT_PERMISSIONS=1 make ops-secret-validate SECRET_ENV=/secure/path/providapt.secrets.env
```

## Render Backend Handoff Artifacts

After validation, generate concrete handoff artifacts for systemd, Docker
Compose, Kubernetes, and Vault:

```bash
make ops-secret-backends \
  SECRET_ENV=/secure/path/providapt.secrets.env \
  OUT_DIR=build/secrets
```

This writes:

| File | Purpose |
| --- | --- |
| `providapt-secrets.systemd.conf` | systemd drop-in using the reviewed env-file path |
| `docker-compose.secrets.override.yml` | Compose override with `env_file` and secret reference |
| `providapt-runtime-secrets.yaml` | Kubernetes Secret and Deployment `envFrom` snippet |
| `providapt-vault-policy.hcl` | least-privilege Vault policy for ProvidAPT runtime reads |
| `providapt-vault-load.sh` | optional KV loader script, redacted unless explicitly enabled |
| `providapt-vault.config.yaml` | config-management snippet for `secrets.provider: vault` references |
| `secret-backend-manifest.json` | machine-readable evidence with variable inventory |

Kubernetes Secret and Vault loader values are redacted by default so generated
artifacts can be reviewed safely. Use `INCLUDE_SECRET_VALUES=1` only inside a
secure deployment pipeline and never commit filled outputs.

## systemd

Place the reviewed file outside the repository:

```bash
sudo install -m 0600 -o root -g root /secure/path/providapt.secrets.env /etc/providapt/providapt.secrets.env
sudo systemctl edit providapt.service
```

Drop-in:

```ini
[Service]
EnvironmentFile=/etc/providapt/providapt.secrets.env
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart providapt.service
```

## Docker Compose

For controlled production-style Compose deployments:

```yaml
services:
  providapt:
    env_file:
      - /secure/path/providapt.secrets.env
```

Prefer Docker secrets or an external secret manager when the environment
supports them. Use env-files only as a simple handoff bridge.

## Kubernetes

Create a secret from the reviewed env-file:

```bash
kubectl create secret generic providapt-runtime-secrets \
  --from-env-file=/secure/path/providapt.secrets.env \
  --namespace providapt
```

Mount it through the Helm chart:

```yaml
extraEnvFrom:
  - secretRef:
      name: providapt-runtime-secrets
```

Keep TLS private keys in a separate Secret with restricted RBAC.

## Vault

Review and apply the generated policy:

```bash
vault policy write providapt-runtime build/secrets/providapt-vault-policy.hcl
```

Load real values only from a secure workstation or deployment pipeline:

```bash
INCLUDE_SECRET_VALUES=1 make ops-secret-backends \
  SECRET_ENV=/secure/path/providapt.secrets.env \
  OUT_DIR=/secure/path/providapt-secret-backends
/secure/path/providapt-secret-backends/providapt-vault-load.sh
```

Then merge `providapt-vault.config.yaml` into the runtime configuration or use
the operator's config-management system to materialize the same
`secrets.vault` keys. Runtime fields can reference those values with
`vault:<key>`.
