# API Authentication

ProvidAPT supports optional API key authentication for REST API endpoints.

## Enabling Authentication

Set the following in `providapt.toml`:

```toml
[api]
rest = ":8080"
auth_enabled = true
auth_keys = ["your-api-key-here"]
```

## Authentication Header

Include the API key in every request:

```bash
curl -H "X-API-Key: your-api-key-here" http://localhost:8080/api/v1/status
```

Alternatively, pass the key as a query parameter:

```bash
curl "http://localhost:8080/api/v1/status?api_key=your-api-key-here"
```

## Role-Based Access

Keys can be assigned roles for fine-grained access control:

```toml
auth_keys = ["admin-key", "analyst-key", "auditor-key"]
auth_roles = { "admin-key" = "admin", "analyst-key" = "analyst", "auditor-key" = "auditor" }
```

### Roles

| Role     | Permissions                                    |
|----------|------------------------------------------------|
| `admin`  | Full access — all endpoints, configuration     |
| `analyst`| Read-only graph/alert data                     |
| `auditor`| Read-only audit logs and status                |

## Security Notes

- API key comparison uses **constant-time** comparison to prevent timing attacks
- Keys are transmitted in plaintext over HTTP — use **TLS in production**
- Rotate keys regularly via `providapt.toml` followed by `POST /api/v1/admin/reload`
