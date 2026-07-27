# RBAC and API Authorization

ProvidAPT supports API key authentication, role-based access control, tenant scoping, and trusted-header SSO for deployments behind an identity-aware reverse proxy.

## Enable API Authentication

```toml
[api]
rest = ":18080"
auth_enabled = true
auth_keys = ["admin-key", "analyst-key", "auditor-key"]
auth_roles = { "admin-key" = "admin", "analyst-key" = "analyst", "auditor-key" = "auditor" }
auth_identities = { "admin-key" = "ops-admin", "analyst-key" = "soc-analyst" }
auth_tenants = { "analyst-key" = "prod" }
```

## Request Authentication

```bash
curl -H "X-API-Key: admin-key" http://localhost:18080/api/v1/status
```

Bearer token syntax is also accepted for API keys:

```bash
curl -H "Authorization: Bearer admin-key" http://localhost:18080/api/v1/status
```

## Built-In Roles

| Role | Intended User | Access |
| --- | --- | --- |
| `admin` | platform administrator | full control-plane access |
| `analyst` | SOC analyst | read-only graph, alert, fleet, policy, delivery, license, and upgrade views |
| `auditor` | compliance reviewer | read-only audit, status, dashboard, and compliance evidence views |

## Custom Roles

```toml
[api.auth_roles]
"operator-key" = "operator"

[api.auth_permissions]
operator = [
  "GET:/api/v1/control/fleet",
  "GET:/api/v1/control/ha",
  "GET:/api/v1/investigation/report",
  "POST:/api/v1/control/alerts"
]
```

Permission entries use `METHOD:/path/prefix`. Use `*` only when a broad role is intentionally approved.

## Tenant Scoping

Tenant-scoped API keys are restricted to the matching fleet group:

```toml
[api.auth_tenants]
"prod-analyst-key" = "prod"
```

Non-admin requests to fleet, audit, and compliance views are filtered by tenant where supported.

## Trusted-Header SSO

Trusted headers are safe only when a reverse proxy authenticates the user and strips untrusted inbound headers:

```toml
[sso]
trusted_header_auth = true
user_header = "X-Forwarded-User"
role_header = "X-Forwarded-Role"
tenant_header = "X-Forwarded-Tenant"
```

## Operational Rules

- Enable TLS before sending API keys or trusted headers over a network.
- Rotate keys through configuration management and reload or restart the service.
- Keep admin keys out of scripts used by analysts.
- Prefer tenant-scoped keys for customer-facing or managed-service use.
- Review custom wildcard permissions before production approval.

## Production RBAC Audit

Run the RBAC audit before customer handoff, release readiness review, and after
every identity-provider or reverse-proxy change:

```bash
make ops-rbac-audit \
  PROVIDAPT_CONFIG=/etc/providapt/providapt.toml \
  OUT_DIR=build/rbac
```

The audit blocks production readiness when API authentication is disabled,
configured keys have no roles, custom permissions are malformed, or custom roles
use unrestricted wildcard access. It warns when non-admin keys are not
tenant-scoped or when keys are missing operator identities.

Outputs:

| File | Purpose |
| --- | --- |
| `rbac-audit.json` | Machine-readable status, role counts, tenant-scoped key count, failures, and warnings |
| `rbac-audit.md` | Reviewer-facing checklist for security and customer handoff |

Attach the JSON output to `make enterprise-readiness` with
`RBAC_AUDIT_JSON=build/rbac/rbac-audit.json` when the file is not in the default
location.
