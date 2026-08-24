#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.security_hardening_gate.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8-sig", errors="replace")


def load_json(path: str) -> dict[str, Any]:
    if not path:
        return {}
    target = Path(path)
    if not target.exists() or target.stat().st_size == 0:
        return {}
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def strip_inline_comment(value: str) -> str:
    in_quote = ""
    out: list[str] = []
    for char in value:
        if char in {"'", '"'}:
            in_quote = "" if in_quote == char else (char if not in_quote else in_quote)
        if char == "#" and not in_quote:
            break
        out.append(char)
    return "".join(out).strip()


def clean_scalar(value: str) -> str:
    value = strip_inline_comment(value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_config_sections(data: str) -> dict[str, dict[str, Any]]:
    sections: dict[str, dict[str, Any]] = {}
    current_section = ""
    current_key = ""
    for line in data.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 0 and stripped.endswith(":"):
            current_section = stripped[:-1]
            current_key = ""
            sections.setdefault(current_section, {})
            continue
        if not current_section or indent < 2:
            continue
        section = sections.setdefault(current_section, {})
        if stripped.startswith("- "):
            if current_key:
                section.setdefault(current_key, [])
                if isinstance(section[current_key], list):
                    section[current_key].append(clean_scalar(stripped[2:]))
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        current_key = key.strip()
        value = clean_scalar(value)
        section[current_key] = [] if value == "" else value
    return sections


def truthy(value: Any) -> bool:
    return str(value).strip().lower() == "true"


def has_value(section: dict[str, Any], key: str) -> bool:
    value = section.get(key)
    if isinstance(value, list):
        return bool(value)
    return bool(str(value or "").strip())


def placeholder_values(values: list[Any]) -> list[str]:
    markers = ("replace-with", "change-me", "changeme", "example.com", "<")
    hits: list[str] = []
    for value in values:
        if isinstance(value, dict):
            hits.extend(placeholder_values(list(value.values())))
            continue
        if isinstance(value, list):
            hits.extend(placeholder_values(value))
            continue
        text = str(value or "")
        if any(marker in text for marker in markers):
            hits.append(text)
    return hits


def check_config(path: Path) -> dict[str, Any]:
    data = read(path)
    failures: list[str] = []
    warnings: list[str] = []
    if not data:
        failures.append("production config is missing")
        return {"status": "blocked", "path": str(path), "failures": failures, "warnings": warnings}

    cfg = parse_config_sections(data)
    api = cfg.get("api", {})
    tls = cfg.get("tls", {})
    telemetry = cfg.get("telemetry", {})
    policy = cfg.get("policy", {})
    storage = cfg.get("storage", {})
    compliance = cfg.get("compliance", {})
    support = cfg.get("support_bundle", {})
    secrets = cfg.get("secrets", {})

    cors = api.get("cors_origins") or []
    if not isinstance(cors, list) or not cors:
        failures.append("api.cors_origins must restrict browser origins")
    elif "*" in cors:
        failures.append("api.cors_origins must not include wildcard '*'")

    if not truthy(tls.get("enable")):
        failures.append("tls.enable must be true")
    for key in ("cert_file", "key_file", "ca_file"):
        if not has_value(tls, key):
            failures.append(f"tls.{key} is required")
    for key in ("rotation_check", "rotation_renew_before"):
        if not has_value(tls, key):
            failures.append(f"tls.{key} is required")
    if not truthy(tls.get("rotation_auto")):
        warnings.append("tls.rotation_auto is not enabled; certificate rotation remains operator-driven")

    if not truthy(telemetry.get("enable_tls")):
        failures.append("telemetry.enable_tls must be true for agent/server traffic")
    for key in ("cert_file", "key_file", "ca_file", "server_name"):
        if not has_value(telemetry, key):
            failures.append(f"telemetry.{key} is required")

    if not truthy(policy.get("enable_tls")):
        failures.append("policy.enable_tls must be true")
    if not str(policy.get("endpoint", "")).startswith("https://"):
        failures.append("policy.endpoint must use https")

    if not truthy(storage.get("encrypt")):
        failures.append("storage.encrypt must be true")
    if not truthy(compliance.get("require_approvals")):
        failures.append("compliance.require_approvals must be true")
    if not truthy(support.get("redact_archives")):
        failures.append("support_bundle.redact_archives must be true")

    provider = str(secrets.get("provider", "")).strip().lower()
    if provider not in {"file", "vault"}:
        failures.append("secrets.provider must be file or vault for production")
    if provider == "file" and not has_value(secrets, "base_dir"):
        failures.append("secrets.base_dir is required for file-backed secrets")

    placeholders = placeholder_values([cfg.get("control_plane", {}).get("state_backend", "")])
    if placeholders:
        warnings.append("placeholder values remain in sensitive fields: " + ", ".join(sorted(set(placeholders))[:5]))
    return {"status": "blocked" if failures else ("warn" if warnings else "pass"), "path": str(path), "failures": failures, "warnings": warnings}


def check_systemd(path: Path) -> dict[str, Any]:
    data = read(path)
    failures: list[str] = []
    warnings: list[str] = []
    if not data:
        failures.append("systemd service is missing")
    for marker in ["PrivateTmp=true", "ProtectHome=true", "RuntimeDirectory=providapt", "ReadWritePaths="]:
        if marker not in data:
            failures.append(f"missing systemd hardening marker {marker}")
    for marker in ["NoNewPrivileges=false", "ProtectKernelTunables=false", "ProtectKernelModules=false", "ProtectControlGroups=false"]:
        if marker in data:
            warnings.append(f"{marker} is required for some eBPF modes; document approval before GA")
    if "CapabilityBoundingSet=" not in data:
        failures.append("CapabilityBoundingSet is missing")
    return {"status": "blocked" if failures else ("warn" if warnings else "pass"), "path": str(path), "failures": failures, "warnings": warnings}


def check_env(path: Path) -> dict[str, Any]:
    data = read(path)
    failures: list[str] = []
    warnings: list[str] = []
    if not data:
        failures.append("service environment file is missing")
    if 'PROVIDAPT_SKIP_PRIVILEGE_DROP=""' not in data:
        warnings.append("privilege drop default is not visibly locked on")
    if 'PROVIDAPT_SKIP_SANITY_CHECKS=""' not in data:
        warnings.append("sanity check bypass default is not visibly empty")
    return {"status": "blocked" if failures else ("warn" if warnings else "pass"), "path": str(path), "failures": failures, "warnings": warnings}


def check_rbac(report: dict[str, Any]) -> dict[str, Any]:
    if not report:
        return {"status": "skipped", "message": "RBAC audit not supplied"}
    status = str(report.get("status", "")).lower()
    failures = list(report.get("failures") or [])
    warnings = list(report.get("warnings") or [])
    if status == "blocked":
        return {"status": "blocked", "failures": failures or ["RBAC audit is blocked"], "warnings": warnings}
    if status == "warn" or warnings:
        return {"status": "warn", "failures": [], "warnings": warnings}
    return {"status": "pass", "failures": [], "warnings": []}


def overall(sections: dict[str, dict[str, Any]]) -> str:
    statuses = [section.get("status") for section in sections.values() if section.get("status") != "skipped"]
    if "blocked" in statuses:
        return "blocked"
    if "warn" in statuses:
        return "warn"
    return "pass"


def apply_strict_mode(sections: dict[str, dict[str, Any]]) -> None:
    for name, section in sections.items():
        if section.get("status") == "skipped":
            section["status"] = "blocked"
            section.setdefault("failures", []).append(f"{name} evidence is required in strict mode")
            continue
        warnings = list(section.get("warnings") or [])
        if warnings:
            section.setdefault("failures", []).extend("strict mode blocks warning: " + item for item in warnings)
            section["status"] = "blocked"


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# ProvidAPT Security Hardening Gate", "", f"- Status: `{report['status']}`", f"- Generated at: `{report['generated_at']}`", f"- Strict mode: `{report.get('strict', False)}`", ""]
    for name, section in report["sections"].items():
        lines.extend([f"## {name.replace('_', ' ').title()}", "", f"- Status: `{section['status']}`"])
        if section.get("failures"):
            lines.append("- Failures: " + "; ".join(section["failures"]))
        if section.get("warnings"):
            lines.append("- Warnings: " + "; ".join(section["warnings"]))
        if section.get("message"):
            lines.append("- Message: " + str(section["message"]))
        lines.append("")
    return "\n".join(lines)


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    sections = {
        "configuration": check_config(Path(args.config)),
        "systemd_sandbox": check_systemd(Path(args.service)),
        "environment": check_env(Path(args.env_file)),
        "rbac": check_rbac(load_json(args.rbac_audit)),
    }
    if getattr(args, "strict", False):
        apply_strict_mode(sections)
    return {"schema": SCHEMA, "generated_at": utc_now(), "status": overall(sections), "strict": bool(getattr(args, "strict", False)), "sections": sections}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate production security hardening evidence.")
    parser.add_argument("--config", default="examples/config/providapt.production.yaml")
    parser.add_argument("--service", default="deploy/linux/providapt.service")
    parser.add_argument("--env-file", default="deploy/linux/providapt.env")
    parser.add_argument("--rbac-audit", default="")
    parser.add_argument("--strict", action="store_true", help="Block on warnings and require optional hardening evidence such as RBAC audit")
    parser.add_argument("--out-json", default="build/security-hardening/security-hardening-gate.json")
    parser.add_argument("--out-md", default="build/security-hardening/security-hardening-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} sections={','.join(report['sections'])}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
