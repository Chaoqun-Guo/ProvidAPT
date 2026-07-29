#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.install_delivery_check.v1"
REQUIRED_BINS = ["providaptd", "providaptctl", "providapt-verify"]
REQUIRED_DOCS = [
    "docs/getting-started/install.md",
    "docs/getting-started/commercial-install.md",
    "docs/user-guide/operations.md",
    "docs/user-guide/troubleshooting.md",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8-sig", errors="replace")


def file_status(path: Path, required: bool = True) -> dict[str, Any]:
    exists = path.exists() and path.is_file()
    return {
        "path": str(path),
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
        "status": "pass" if exists or not required else "fail",
    }


def check_binaries(bin_dir: Path, strict: bool) -> dict[str, Any]:
    items = {name: file_status(bin_dir / name, required=strict) for name in REQUIRED_BINS}
    failures = [f"missing binary {name}" for name, status in items.items() if status["status"] == "fail"]
    return {"status": "pass" if not failures else "blocked", "items": items, "failures": failures}


def check_config(config: Path) -> dict[str, Any]:
    status = file_status(config)
    text = read_text(config)
    failures: list[str] = []
    warnings: list[str] = []
    if status["status"] == "fail":
        failures.append("production config is missing")
    for placeholder in ("replace-with", "change-me", "example.com"):
        if placeholder in text:
            warnings.append(f"config still contains placeholder marker {placeholder}")
    for required in ("auth_enabled: true", "enable: true", "encrypt: true"):
        if required not in text:
            warnings.append(f"config does not visibly include {required}")
    return {"status": "blocked" if failures else ("warn" if warnings else "pass"), "path": str(config), "failures": failures, "warnings": warnings}


def check_systemd(service: Path, env_file: Path) -> dict[str, Any]:
    service_text = read_text(service)
    env_text = read_text(env_file)
    failures: list[str] = []
    warnings: list[str] = []
    required_service = ["ExecStart=", "EnvironmentFile=", "Restart=on-failure", "RuntimeDirectory=providapt"]
    for item in required_service:
        if item not in service_text:
            failures.append(f"systemd service missing {item}")
    for item in ["PrivateTmp=true", "ProtectHome=true", "ReadWritePaths="]:
        if item not in service_text:
            warnings.append(f"systemd service missing hardening setting {item}")
    if "PROVIDAPT_SKIP_PRIVILEGE_DROP=\"\"" not in env_text and "PROVIDAPT_SKIP_PRIVILEGE_DROP=" not in env_text:
        warnings.append("environment file does not document privilege drop")
    status = "blocked" if failures else ("warn" if warnings else "pass")
    return {"status": status, "service": str(service), "env_file": str(env_file), "failures": failures, "warnings": warnings}


def check_docs(root: Path) -> dict[str, Any]:
    items = {doc: file_status(root / doc) for doc in REQUIRED_DOCS}
    failures = [f"missing handoff doc {doc}" for doc, status in items.items() if status["status"] == "fail"]
    return {"status": "pass" if not failures else "blocked", "items": items, "failures": failures}


def overall(sections: dict[str, dict[str, Any]]) -> str:
    statuses = [section.get("status") for section in sections.values()]
    if "blocked" in statuses:
        return "blocked"
    if "warn" in statuses:
        return "warn"
    return "pass"


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# ProvidAPT Install Delivery Check", "", f"- Status: `{report['status']}`", f"- Generated at: `{report['generated_at']}`", ""]
    for name, section in report["sections"].items():
        lines.extend([f"## {name.replace('_', ' ').title()}", "", f"- Status: `{section['status']}`"])
        for key in ("failures", "warnings"):
            if section.get(key):
                lines.append(f"- {key.title()}: " + "; ".join(section[key]))
        lines.append("")
    return "\n".join(lines)


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root)
    sections = {
        "binaries": check_binaries(Path(args.bin_dir), args.strict_binaries),
        "configuration": check_config(Path(args.config)),
        "systemd": check_systemd(Path(args.service), Path(args.env_file)),
        "handoff_docs": check_docs(root),
    }
    return {"schema": SCHEMA, "generated_at": utc_now(), "status": overall(sections), "sections": sections}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate install delivery assets before customer handoff.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--bin-dir", default="build/bin")
    parser.add_argument("--config", default="examples/config/providapt.production.yaml")
    parser.add_argument("--service", default="deploy/linux/providapt.service")
    parser.add_argument("--env-file", default="deploy/linux/providapt.env")
    parser.add_argument("--strict-binaries", action="store_true")
    parser.add_argument("--out-json", default="build/install-delivery/install-delivery-check.json")
    parser.add_argument("--out-md", default="build/install-delivery/install-delivery-check.md")
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
