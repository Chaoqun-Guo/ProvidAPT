#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError


SCHEMA = "providapt.activation_server_gate.v1"


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        if not isinstance(record, dict):
            raise SystemExit(f"{path}:{line_no}: expected JSON object")
        records.append(record)
    return records


def registry_detail(path: str) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    if not path:
        return {"status": "blocked", "failures": ["customer registry path is required"], "warnings": warnings}
    registry_path = Path(path)
    if not registry_path.exists():
        return {"status": "blocked", "path": path, "failures": [f"customer registry is missing: {path}"], "warnings": warnings}
    registry = load_json(registry_path)
    customers = registry.get("customers")
    if not isinstance(customers, list) or not customers:
        failures.append("customer registry must contain at least one entitlement")
        customers = []
    seen_codes: set[str] = set()
    seen_license_ids: set[str] = set()
    disabled = 0
    fingerprint_scoped = 0
    for index, item in enumerate(customers, 1):
        if not isinstance(item, dict):
            failures.append(f"entitlement #{index} is not an object")
            continue
        code = str(item.get("activation_code") or "").strip()
        customer = str(item.get("customer") or "").strip()
        license_id = str(item.get("license_id") or "").strip()
        if not code:
            failures.append(f"entitlement #{index} missing activation_code")
        elif code in seen_codes:
            failures.append(f"duplicate activation_code in entitlement #{index}")
        seen_codes.add(code)
        if not customer:
            failures.append(f"entitlement #{index} missing customer")
        if not license_id:
            failures.append(f"entitlement #{index} missing license_id")
        elif license_id in seen_license_ids:
            failures.append(f"duplicate license_id {license_id}")
        seen_license_ids.add(license_id)
        if int(item.get("max_agents") or 0) <= 0:
            failures.append(f"entitlement #{index} max_agents must be positive")
        if int(item.get("valid_days") or 0) <= 0:
            failures.append(f"entitlement #{index} valid_days must be positive")
        fingerprints = item.get("allowed_fingerprints") or []
        if fingerprints:
            fingerprint_scoped += 1
            if not isinstance(fingerprints, list) or any(not str(value).strip() for value in fingerprints):
                failures.append(f"entitlement #{index} has invalid allowed_fingerprints")
        else:
            warnings.append(f"entitlement #{index} allows any machine fingerprint")
        if item.get("disabled"):
            disabled += 1
    return {
        "status": "pass" if not failures else "blocked",
        "path": str(registry_path),
        "entitlements": len(customers),
        "disabled": disabled,
        "fingerprint_scoped": fingerprint_scoped,
        "failures": failures,
        "warnings": warnings,
    }


def audit_detail(path: str, allow_missing: bool) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    if not path:
        failures.append("activation audit path is required")
        return {"status": "blocked", "failures": failures, "warnings": warnings}
    audit_path = Path(path)
    if not audit_path.exists():
        if allow_missing:
            warnings.append(f"activation audit is missing: {path}")
            return {"status": "warn", "path": path, "records": 0, "failures": failures, "warnings": warnings}
        return {"status": "blocked", "path": path, "records": 0, "failures": [f"activation audit is missing: {path}"], "warnings": warnings}
    records = load_jsonl(audit_path)
    issued = sum(1 for record in records if record.get("status") == "issued")
    rejected = sum(1 for record in records if record.get("status") == "rejected")
    hashed_codes = sum(1 for record in records if record.get("activation_code_sha256"))
    raw_code_fields = sum(1 for record in records if "activation_code" in record)
    if not records:
        failures.append("activation audit contains no records")
    if issued < 1:
        failures.append("activation audit must include at least one issued activation")
    if rejected < 1:
        failures.append("activation audit must include at least one rejected activation")
    if hashed_codes < len(records):
        failures.append("all activation audit records must include activation_code_sha256")
    if raw_code_fields:
        failures.append("activation audit must not store raw activation_code values")
    return {
        "status": "pass" if not failures else "blocked",
        "path": str(audit_path),
        "records": len(records),
        "issued": issued,
        "rejected": rejected,
        "hashed_codes": hashed_codes,
        "failures": failures,
        "warnings": warnings,
    }


def live_probe_detail(args: argparse.Namespace) -> dict[str, Any]:
    if not args.server:
        return {"status": "skipped", "message": "live activation probe not requested"}
    failures: list[str] = []
    warnings: list[str] = []
    payload = {
        "activation_code": args.activation_code,
        "machine_fingerprint": args.machine_fingerprint or "providapt-gate-fingerprint",
    }
    if not args.activation_code:
        failures.append("--activation-code is required when --server is supplied")
        return {"status": "blocked", "failures": failures, "warnings": warnings}
    status, body = post_json(args.server.rstrip("/") + "/v1/activate", payload, args.api_key, args.timeout_seconds)
    if status != 200:
        failures.append(f"positive activation probe returned HTTP {status}")
    elif body.get("status") != "issued" or not (body.get("license") or {}).get("signature"):
        failures.append("positive activation probe did not return issued license with signature")
    if args.negative_fingerprint:
        negative = dict(payload)
        negative["machine_fingerprint"] = args.negative_fingerprint
        negative_status, _ = post_json(args.server.rstrip("/") + "/v1/activate", negative, args.api_key, args.timeout_seconds)
        if negative_status not in {401, 403}:
            failures.append(f"negative activation probe returned HTTP {negative_status}, want 401 or 403")
    return {
        "status": "pass" if not failures else "blocked",
        "server": args.server,
        "positive_http_status": status,
        "negative_probe": bool(args.negative_fingerprint),
        "failures": failures,
        "warnings": warnings,
    }


def post_json(url: str, payload: dict[str, Any], api_key: str, timeout_seconds: float) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with request.urlopen(req, timeout=timeout_seconds) as resp:
            body = json.loads(resp.read().decode("utf-8") or "{}")
            return resp.status, body if isinstance(body, dict) else {}
    except HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8") or "{}")
        except json.JSONDecodeError:
            body = {}
        return exc.code, body if isinstance(body, dict) else {}
    except URLError as exc:
        return 0, {"error": str(exc)}


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    registry = registry_detail(args.customer_registry)
    audit = audit_detail(args.activation_audit, args.allow_missing_audit)
    live_probe = live_probe_detail(args)
    failures = []
    for section in (registry, audit, live_probe):
        failures.extend(section.get("failures", []))
    status = "pass" if not failures else "blocked"
    if status == "pass" and (registry.get("warnings") or audit.get("warnings") or live_probe.get("warnings")):
        status = "warn"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "registry": registry,
        "audit": audit,
        "live_probe": live_probe,
        "failures": failures,
        "warnings": registry.get("warnings", []) + audit.get("warnings", []) + live_probe.get("warnings", []),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Activation Server Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Entitlements: `{report['registry'].get('entitlements', 0)}`",
        f"- Audit records: `{report['audit'].get('records', 0)}`",
        f"- Live probe: `{report['live_probe'].get('status')}`",
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
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate activation server registry, audit, and optional live activation probe evidence.")
    parser.add_argument("--customer-registry", required=True)
    parser.add_argument("--activation-audit", default="build/auth/activations.jsonl")
    parser.add_argument("--allow-missing-audit", action="store_true")
    parser.add_argument("--server")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--activation-code", default="")
    parser.add_argument("--machine-fingerprint", default="providapt-gate-fingerprint")
    parser.add_argument("--negative-fingerprint", default="")
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--out-json", default="build/activation/activation-server-gate.json")
    parser.add_argument("--out-md", default="build/activation/activation-server-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"activation server gate: status={report['status']} entitlements={report['registry'].get('entitlements', 0)}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
