#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.rbac_audit.v1"
SAFE_ROLES = {"admin", "analyst", "auditor", "operator"}
PERMISSION_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|\*):(/|\*)")


def load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"{path}: invalid TOML: {exc}") from exc


def as_map(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def audit_config(config: dict[str, Any], path: Path) -> dict[str, Any]:
    api = as_map(config.get("api"))
    sso = as_map(config.get("sso"))
    auth_keys = [str(item) for item in as_list(api.get("auth_keys")) if str(item).strip()]
    auth_roles = {str(key): str(value) for key, value in as_map(api.get("auth_roles")).items()}
    auth_identities = {str(key): str(value) for key, value in as_map(api.get("auth_identities")).items()}
    auth_tenants = {str(key): str(value) for key, value in as_map(api.get("auth_tenants")).items()}
    custom_permissions = as_map(api.get("auth_permissions"))
    failures: list[str] = []
    warnings: list[str] = []
    role_counts: dict[str, int] = {}
    tenant_scopes: dict[str, list[str]] = {}

    if not bool(api.get("auth_enabled")):
        failures.append("api.auth_enabled must be true for production")
    if not auth_keys:
        failures.append("api.auth_keys must define at least one key")
    for key in auth_keys:
        role = auth_roles.get(key, "")
        if not role:
            failures.append(f"auth key {key} has no assigned role")
            continue
        role_counts[role] = role_counts.get(role, 0) + 1
        if role not in SAFE_ROLES and role not in custom_permissions:
            failures.append(f"auth key {key} uses unknown role {role}")
        if role != "admin" and not auth_tenants.get(key):
            warnings.append(f"non-admin key {key} has no tenant scope")
        if auth_tenants.get(key):
            tenant_scopes[key] = split_scope(auth_tenants[key])
        if not auth_identities.get(key):
            warnings.append(f"auth key {key} has no operator identity")
    for key in auth_roles:
        if key not in auth_keys:
            warnings.append(f"role mapping exists for unknown key {key}")
    for role, permissions in custom_permissions.items():
        if not isinstance(permissions, list):
            failures.append(f"custom role {role} permissions must be a list")
            continue
        for permission in permissions:
            permission_text = str(permission)
            if permission_text in {"*", "*:*"}:
                failures.append(f"custom role {role} uses unrestricted wildcard permission")
            elif not PERMISSION_RE.match(permission_text):
                failures.append(f"custom role {role} has invalid permission {permission_text}")
            elif permission_text.endswith("*"):
                warnings.append(f"custom role {role} uses broad prefix permission {permission_text}")
    if bool(sso.get("trusted_header_auth")):
        missing = [name for name in ("user_header", "role_header") if not str(sso.get(name, "")).strip()]
        if missing:
            failures.append("trusted-header SSO is missing " + ", ".join(missing))
        if not str(sso.get("tenant_header", "")).strip():
            warnings.append("trusted-header SSO has no tenant header")
    status = "pass" if not failures else "blocked"
    if status == "pass" and warnings:
        status = "warn"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "config_path": str(path),
        "auth_enabled": bool(api.get("auth_enabled")),
        "key_count": len(auth_keys),
        "tenant_scoped_keys": len(auth_tenants),
        "tenant_count": len({tenant for scope in tenant_scopes.values() for tenant in scope}),
        "tenant_scopes": tenant_scopes,
        "custom_role_count": len(custom_permissions),
        "role_counts": role_counts,
        "trusted_header_sso": bool(sso.get("trusted_header_auth")),
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT RBAC Audit",
        "",
        f"- Status: `{report['status']}`",
        f"- Config: `{report['config_path']}`",
        f"- API auth enabled: `{report['auth_enabled']}`",
        f"- API keys: `{report['key_count']}`",
        f"- Tenant-scoped keys: `{report['tenant_scoped_keys']}`",
        f"- Tenants: `{report.get('tenant_count', 0)}`",
        f"- Custom roles: `{report['custom_role_count']}`",
        f"- Trusted-header SSO: `{report['trusted_header_sso']}`",
        "",
    ]
    if report["failures"]:
        lines.extend(["## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
        lines.append("")
    if report["warnings"]:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {item}" for item in report["warnings"])
        lines.append("")
    lines.extend(["## Role Counts", ""])
    if report["role_counts"]:
        lines.extend(f"- `{role}`: {count}" for role, count in sorted(report["role_counts"].items()))
    else:
        lines.append("- No roles configured")
    lines.append("")
    if report.get("tenant_scopes"):
        lines.extend(["## Tenant Scopes", ""])
        for key, scope in sorted(report["tenant_scopes"].items()):
            lines.append(f"- `{key}`: {', '.join(scope)}")
        lines.append("")
    return "\n".join(lines)


def split_scope(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[,;]", value) if item.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit production RBAC, tenant scoping, and trusted-header SSO configuration.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--out-json", default="build/rbac/rbac-audit.json")
    parser.add_argument("--out-md", default="build/rbac/rbac-audit.md")
    args = parser.parse_args()
    report = audit_config(load_toml(Path(args.config)), Path(args.config))
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} keys={report['key_count']} tenants={report['tenant_scoped_keys']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
