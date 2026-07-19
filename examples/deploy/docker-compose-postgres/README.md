# Docker Compose with PostgreSQL

This example describes a PostgreSQL-backed control-plane lab deployment.

## Compose File

Use the local `docker-compose.yml` in this directory for a PostgreSQL-backed lab.

Recommended environment:

```bash
export PROVIDAPT_DATABASE_DSN='postgres://providapt:providapt@postgres:5432/providapt?sslmode=disable'
export PROVIDAPT_AUTH_ENABLED=true
export PROVIDAPT_TLS_ENABLED=false
cd examples/deploy/docker-compose-postgres
docker compose up -d postgres
docker compose up -d providapt
```

## Health Checks

```bash
docker compose ps
docker compose logs --tail=100 providapt
docker compose exec postgres pg_isready -U providapt
curl -s http://localhost:18080/api/v1/status
```

## Notes

- Use Docker secrets or an external secret manager for production credentials.
- Enable TLS and authentication before exposing the control plane outside a private lab.
- Configure retention and backup before collecting customer data.
