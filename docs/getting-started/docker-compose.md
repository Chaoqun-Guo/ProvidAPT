# Docker Compose Deployment

This guide describes a local production-style Docker Compose deployment for evaluation and small controlled environments.

## Prerequisites

- Linux host with BPF-capable kernel.
- Docker Engine and Docker Compose plugin.
- Access to `/sys`, `/sys/fs/bpf`, and `/sys/kernel/btf/vmlinux`.
- PostgreSQL enabled for production-like control-plane state.

## Start PostgreSQL and ProvidAPT

Use the PostgreSQL example compose file:

```bash
cd examples/deploy/docker-compose-postgres
docker compose up -d postgres
docker compose up -d providapt
```

The root `docker-compose.yml` remains useful for local build, shell, and test workflows.

## Start Activation and Upgrade Services

The root compose file also includes the Docker-based activation server used by the dashboard for online activation, revocation checks, and upgrade manifest discovery:

```bash
docker compose up -d auth-server
docker compose up -d postgres providapt
```

See [license-activation-server.md](license-activation-server.md) for signing keys, activation codes, revocation IDs, and release manifest settings.

## Required Environment

```bash
export PROVIDAPT_DATABASE_DSN='postgres://providapt:providapt@postgres:5432/providapt?sslmode=disable'
export PROVIDAPT_AUTH_ENABLED=true
export PROVIDAPT_TLS_ENABLED=false
```

For production, use Docker secrets or the customer's secret manager instead of shell environment variables.

Generate a placeholder secret template before wiring the deployment pipeline:

```bash
make ops-secret-template
make ops-secret-validate SECRET_ENV=/secure/path/providapt.secrets.env
```

Do not mount `build/providapt.secrets.env.example` directly into production. It
contains placeholders and exists only to document required secret names.
Mount a reviewed env-file with `env_file` only in controlled environments; use
Docker secrets or an external secret manager when available.

## Health Checks

```bash
docker compose ps
docker compose logs --tail=100 providapt
docker compose exec postgres pg_isready -U providapt
curl -s http://localhost:18080/api/v1/status
```

## Monitoring Profile

Start Prometheus and Grafana when the compose file includes the monitoring profile:

```bash
docker compose --profile monitoring up -d prometheus grafana
```

Default URLs:

- ProvidAPT: `http://localhost:18080/`
- Prometheus: `http://localhost:9090/`
- Grafana: `http://localhost:3000/`

## Stop and Remove

```bash
docker compose down
```

Remove volumes only when data loss is acceptable:

```bash
docker compose down -v
```

## Production Notes

- Enable TLS and authentication before exposing the dashboard outside a private network.
- Check TLS expiry with `make ops-tls-check CERTS="/path/server.crt /path/agent.crt"` during rollout.
- Persist PostgreSQL data on durable storage.
- Run `make ops-postgres-drill` against a staging restore database before customer handoff.
- Configure backups and retention before collecting customer data.
- Avoid privileged containers unless the deployment explicitly requires host eBPF capture.
