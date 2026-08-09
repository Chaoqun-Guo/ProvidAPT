# API Authentication

ProvidAPT supports API key authentication, role-based access control, tenant scoping, and optional trusted-header SSO for deployments behind a reverse proxy or identity gateway.

## Enabling API Keys

Set the following in `providapt.toml`:

```toml
[api]
rest = ":18080"
auth_enabled = true
auth_keys = ["admin-key", "analyst-key", "auditor-key"]
auth_roles = { "admin-key" = "admin", "analyst-key" = "analyst", "auditor-key" = "auditor" }
auth_identities = { "admin-key" = "ops-admin", "analyst-key" = "soc-analyst" }
auth_tenants = { "analyst-key" = "prod" }
```

## Authentication Header

Include the API key in every request:

```bash
curl -H "X-API-Key: admin-key" http://localhost:18080/api/v1/status
```

Alternatively, pass the key as a query parameter:

```bash
curl "http://localhost:18080/api/v1/status?api_key=admin-key"
```

Bearer token syntax is also accepted:

```bash
curl -H "Authorization: Bearer admin-key" http://localhost:18080/api/v1/status
```

## Roles

| Role | Permissions |
| --- | --- |
| `admin` | Full access to all endpoints and operational actions. |
| `operator` | Scoped fleet, alert, upgrade, and read-only investigation operations for managed-service use. |
| `analyst` | Read-only graph, alert, fleet, policy, delivery, and upgrade views; no administrative mutations. |
| `auditor` | Read-only audit, status, dashboard, and compliance evidence views. |

Custom roles can be declared with explicit method/path permissions:

```toml
[api.auth_roles]
"operator-key" = "operator"

[api.auth_permissions]
operator = [
  "GET:/api/v1/control/fleet",
  "GET:/api/v1/control/ha",
  "GET:/api/v1/investigation/report"
]
```

Permission entries use `METHOD:/path/prefix`; `*` is allowed for either method
or path only when an intentionally broad role is required. Unknown roles without
`api.auth_permissions` are denied.

## Tenant Scoping

Use `api.auth_tenants` to bind an API key to a tenant or fleet group.
Comma-separated values grant one key access to multiple managed tenants:

```toml
[api.auth_tenants]
"mssp-operator-key" = "prod,staging"
```

Non-admin requests to `/api/v1/control/fleet` are restricted to the configured
tenant scope. If a non-admin supplies a different `group`, the API returns
`403`. Fleet writes with multiple tenant scopes must include an explicit
`group`.

## Trusted-Header SSO

Trusted-header SSO is intended only for deployments where a trusted reverse proxy has already authenticated the user and strips untrusted inbound identity headers.

```toml
[sso]
trusted_header_auth = true
user_header = "X-Forwarded-User"
role_header = "X-Forwarded-Role"
tenant_header = "X-Forwarded-Tenant"
```

When enabled, ProvidAPT reads the configured headers and maps the request to an actor, role, and optional tenant. Missing roles default to `admin` for local compatibility; unknown custom roles require matching `api.auth_permissions` entries.

## Security Notes

- API key comparison uses constant-time comparison.
- Use TLS in production; API keys and trusted headers must not traverse plaintext networks.
- Rotate keys through configuration management followed by `POST /api/v1/admin/reload`.
- Do not expose trusted-header SSO directly to users; terminate it only behind a controlled identity proxy.
