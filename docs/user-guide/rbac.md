# Access Control and RBAC

ProvidAPT is now fully open-source and no longer ships a built-in credential gate
for the local control plane. Operators should protect the dashboard and REST API
with network controls, TLS, host firewall rules, Tailscale ACLs, or an
identity-aware reverse proxy.

## Built-In Roles

The daemon still uses roles internally so trusted reverse proxies can pass an
operator identity into audit records and permission checks.

| Role | Intended User | Access |
| --- | --- | --- |
| `admin` | platform administrator | full control-plane access |
| `operator` | managed-service operator | scoped fleet, alert, upgrade, and read-only investigation operations |
| `analyst` | SOC analyst | read-only graph, alert, fleet, policy, delivery, and upgrade views |
| `auditor` | compliance reviewer | read-only audit, status, dashboard, and compliance evidence views |

Requests without trusted identity headers run as the default
`open-source-operator` admin actor. This keeps local, VM, and Tailscale lab
deployments usable without local credentials.

## Custom Permissions

Custom roles can still be defined for trusted-header deployments:

```toml
[api.auth_permissions]
operator = [
  "GET:/api/v1/control/fleet",
  "GET:/api/v1/control/ha",
  "GET:/api/v1/investigation/report",
  "POST:/api/v1/control/alerts"
]
```

Permission entries use `METHOD:/path/prefix`. Use `*` only when a broad role is
intentionally approved.

## Trusted-Header SSO

Trusted headers are safe only when a reverse proxy authenticates the user and
strips untrusted inbound headers:

```toml
[sso]
trusted_header_auth = true
user_header = "X-Forwarded-User"
role_header = "X-Forwarded-Role"
tenant_header = "X-Forwarded-Tenant"
```

## Operational Rules

- Restrict dashboard/API reachability with Tailscale ACLs, firewall rules, or a
  reverse proxy.
- Enable TLS before exposing the service beyond a local lab network.
- Do not forward arbitrary inbound trusted headers from clients.
- Review custom wildcard permissions before production approval.

## RBAC Audit

Run the RBAC audit before handoff, release readiness review, and after every
identity-provider or reverse-proxy change:

```bash
make ops-rbac-audit \
  PROVIDAPT_CONFIG=/etc/providapt/providapt.toml \
  OUT_DIR=build/rbac
```

The audit checks trusted-header settings and custom permission syntax. It warns
when no trusted-header SSO is configured so reviewers can confirm equivalent
network and TLS controls.

Outputs:

| File | Purpose |
| --- | --- |
| `rbac-audit.json` | Machine-readable status, custom role counts, failures, and warnings |
| `rbac-audit.md` | Reviewer-facing checklist for security and handoff |
`RBAC_AUDIT_JSON=build/rbac/rbac-audit.json` when the file is not in the default
location.
