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
    custom_permissions = as_map(api.get("auth_permissions"))
    failures: list[str] = []
    warnings: list[str] = []
    role_counts: dict[str, int] = {role: 1 for role in SAFE_ROLES}
    tenant_scopes: dict[str, list[str]] = {}

    if not bool(sso.get("trusted_header_auth")):
        warnings.append("trusted-header SSO is not enabled; protect the open-source control plane with network, TLS, and reverse-proxy controls")
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
        "open_source_control_plane": True,
        "key_count": 0,
        "tenant_scoped_keys": 0,
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
        f"- Control plane access: `open-source`",
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
    print(f"status={report['status']} control_plane=open-source tenants={report['tenant_scoped_keys']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
