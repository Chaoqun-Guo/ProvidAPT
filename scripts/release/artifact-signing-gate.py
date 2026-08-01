#!/usr/bin/env python3
"""Validate release checksum integrity and detached signature evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.artifact_signing_gate.v1"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class ArtifactRecord:
    name: str
    path: str
    expected_sha256: str
    actual_sha256: str
    size_bytes: int
    status: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_artifact_path(dist_dir: Path, raw_name: str) -> tuple[Path | None, str]:
    name = raw_name[1:] if raw_name.startswith("*") else raw_name
    name = name.strip()
    if not name:
        return None, "empty artifact path"
    candidate = Path(name)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None, f"unsafe artifact path: {raw_name}"
    root = dist_dir.resolve()
    resolved = (root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        return None, f"artifact path escapes dist dir: {raw_name}"
    return resolved, ""


def parse_checksums(path: Path, dist_dir: Path) -> tuple[list[tuple[str, Path, str]], list[str]]:
    records: list[tuple[str, Path, str]] = []
    failures: list[str] = []
    if not path.exists() or path.stat().st_size == 0:
        return records, [f"checksum manifest missing or empty: {path}"]
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(maxsplit=1)
        if len(parts) != 2:
            failures.append(f"line {line_number}: expected '<sha256>  <artifact>'")
            continue
        expected, raw_name = parts
        if not SHA256_RE.match(expected):
            failures.append(f"line {line_number}: invalid SHA-256 digest")
            continue
        artifact_path, error = safe_artifact_path(dist_dir, raw_name)
        if error:
            failures.append(f"line {line_number}: {error}")
            continue
        assert artifact_path is not None
        records.append((expected.lower(), artifact_path, raw_name[1:] if raw_name.startswith("*") else raw_name))
    if not records and not failures:
        failures.append("checksum manifest has no artifact entries")
    return records, failures


def validate_artifacts(entries: list[tuple[str, Path, str]], dist_dir: Path) -> tuple[list[ArtifactRecord], list[str]]:
    artifacts: list[ArtifactRecord] = []
    failures: list[str] = []
    for expected, path, display_name in entries:
        if not path.exists() or not path.is_file():
            failures.append(f"missing artifact: {display_name}")
            artifacts.append(ArtifactRecord(display_name, str(path.relative_to(dist_dir.resolve())), expected, "", 0, "missing"))
            continue
        actual = sha256_file(path)
        status = "pass" if actual == expected else "blocked"
        if status != "pass":
            failures.append(f"checksum mismatch: {display_name}")
        artifacts.append(
            ArtifactRecord(
                name=Path(display_name).name,
                path=str(path.relative_to(dist_dir.resolve())),
                expected_sha256=expected,
                actual_sha256=actual,
                size_bytes=path.stat().st_size,
                status=status,
            )
        )
    return artifacts, failures


def classify_signature(signature_path: Path, checksums_path: Path) -> tuple[dict[str, Any], list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    result: dict[str, Any] = {
        "path": str(signature_path),
        "format": "missing",
        "status": "blocked",
        "verification": "not_checked",
    }
    if not signature_path.exists() or signature_path.stat().st_size == 0:
        failures.append(f"signature evidence missing or empty: {signature_path}")
        return result, failures, warnings

    text = signature_path.read_text(encoding="utf-8", errors="replace").strip()
    lower = text.lower()
    result.update({"size_bytes": signature_path.stat().st_size, "status": "pass"})
    if "unsigned checksums" in lower or "signing disabled" in lower:
        result["format"] = "unsigned-marker"
        result["status"] = "blocked"
        failures.append("signature evidence is an unsigned marker")
        return result, failures, warnings

    if text.startswith("{"):
        try:
            bundle = json.loads(text)
        except json.JSONDecodeError as exc:
            result["format"] = "providapt-ed25519-json"
            result["status"] = "blocked"
            failures.append(f"invalid ProvidAPT signature JSON: {exc}")
            return result, failures, warnings
        if not checksums_path.exists() or checksums_path.stat().st_size == 0:
            result.update({"format": "providapt-ed25519", "status": "blocked"})
            failures.append(f"checksum manifest missing or empty: {checksums_path}")
            return result, failures, warnings
        return validate_providapt_ed25519_signature(bundle, checksums_path, result)

    if "-----BEGIN PGP SIGNATURE-----" in text:
        result.update({"format": "gpg-armored", "verification": "detached_signature_present"})
        return result, failures, warnings
    if lower.startswith("untrusted comment: signature from minisign") or lower.startswith("trusted comment:"):
        result.update({"format": "minisign", "verification": "detached_signature_present"})
        return result, failures, warnings
    if '"critical"' in text and '"signature"' in text and ('"payload"' in lower or '"signedentrytimestamp"' in lower):
        result.update({"format": "cosign-bundle", "verification": "bundle_present"})
        return result, failures, warnings

    result.update({"format": "unknown", "status": "warn", "verification": "nonempty_signature_present"})
    warnings.append("signature evidence is non-empty but not a recognized format")
    return result, failures, warnings


def validate_providapt_ed25519_signature(
    bundle: dict[str, Any], checksums_path: Path, result: dict[str, Any]
) -> tuple[dict[str, Any], list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    result.update({"format": "providapt-ed25519", "verification": "structural_and_message_hash"})
    if bundle.get("type") != "providapt-ed25519-checksums-v1":
        failures.append("ProvidAPT signature bundle has unexpected type")
    if bundle.get("algorithm") != "ed25519":
        failures.append("ProvidAPT signature bundle has unexpected algorithm")
    expected_message = sha256_file(checksums_path)
    if str(bundle.get("message_sha256") or "").lower() != expected_message:
        failures.append("ProvidAPT signature bundle is not bound to checksums.txt")
    try:
        public_key = bytes.fromhex(str(bundle.get("public_key") or ""))
    except ValueError:
        public_key = b""
    if len(public_key) != 32:
        failures.append("ProvidAPT signature bundle public_key is not 32 bytes")
    try:
        signature = base64.b64decode(str(bundle.get("signature") or ""), validate=True)
    except ValueError:
        signature = b""
    if len(signature) != 64:
        failures.append("ProvidAPT signature bundle signature is not 64 bytes")
    if not bundle.get("created_at"):
        warnings.append("ProvidAPT signature bundle has no created_at timestamp")
    result["message_sha256"] = str(bundle.get("message_sha256") or "")
    result["public_key_sha256"] = hashlib.sha256(public_key).hexdigest() if public_key else ""
    if failures:
        result["status"] = "blocked"
    return result, failures, warnings


def artifact_matches_required_type(path: str, required_type: str) -> bool:
    name = Path(path).name.lower()
    token = required_type.lower()
    if token == "archive":
        return name.endswith((".tar.gz", ".tgz", ".zip"))
    if token == "deb":
        return name.endswith(".deb")
    if token == "rpm":
        return name.endswith(".rpm")
    if token == "helm":
        return "helm" in name or name.endswith(".tgz")
    if token == "monitoring":
        return "monitoring" in name or "prometheus" in name or "grafana" in name
    if token == "sbom":
        return name.endswith(".spdx.json") or name.endswith(".cdx.json")
    return token in name


def validate_required_artifacts(artifacts: list[ArtifactRecord], required: list[str]) -> list[str]:
    present = [artifact.path for artifact in artifacts if artifact.status == "pass"]
    failures: list[str] = []
    for required_type in required:
        if not any(artifact_matches_required_type(path, required_type) for path in present):
            failures.append(f"missing required artifact type: {required_type}")
    return failures


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    dist_dir = Path(args.dist_dir).resolve()
    checksums = Path(args.checksums)
    signature = Path(args.signature)
    if not checksums.is_absolute():
        checksums = Path.cwd() / checksums
    if not signature.is_absolute():
        signature = Path.cwd() / signature
    entries, failures = parse_checksums(checksums, dist_dir)
    artifacts, artifact_failures = validate_artifacts(entries, dist_dir)
    failures.extend(artifact_failures)
    failures.extend(validate_required_artifacts(artifacts, list(args.required_artifact or [])))
    signature_result, signature_failures, warnings = classify_signature(signature, checksums)
    failures.extend(signature_failures)
    status = "blocked" if failures else "warn" if warnings or signature_result.get("status") == "warn" else "pass"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": status,
        "dist_dir": str(dist_dir),
        "checksums": str(checksums),
        "artifact_count": len(artifacts),
        "signature": signature_result,
        "required_artifacts": list(args.required_artifact or []),
        "failures": failures,
        "warnings": warnings,
        "artifacts": [asdict(artifact) for artifact in artifacts],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Artifact Signing Gate",
        "",
        f"Generated: {report['generated_at']}",
        f"Status: `{report['status']}`",
        f"Checksum manifest: `{report['checksums']}`",
        f"Signature format: `{report['signature'].get('format', '')}`",
        f"Signature verification: `{report['signature'].get('verification', '')}`",
        "",
    ]
    if report["failures"]:
        lines.extend(["## Failures", "", *[f"- {failure}" for failure in report["failures"]], ""])
    if report["warnings"]:
        lines.extend(["## Warnings", "", *[f"- {warning}" for warning in report["warnings"]], ""])
    lines.extend(
        [
            "## Artifacts",
            "",
            "| Artifact | Status | Size | SHA-256 |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for artifact in report["artifacts"]:
        lines.append(
            "| {path} | {status} | {size} | `{sha}` |".format(
                path=str(artifact["path"]).replace("|", "\\|"),
                status=artifact["status"],
                size=artifact["size_bytes"],
                sha=artifact["actual_sha256"] or artifact["expected_sha256"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate release checksums and detached signature evidence.")
    parser.add_argument("--dist-dir", default="dist")
    parser.add_argument("--checksums", default="dist/checksums.txt")
    parser.add_argument("--signature", default="dist/checksums.txt.sig")
    parser.add_argument("--required-artifact", action="append", default=[])
    parser.add_argument("--out-json", default="build/artifact-signing/artifact-signing-gate.json")
    parser.add_argument("--out-md", default="build/artifact-signing/artifact-signing-gate.md")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"artifact signing gate: status={report['status']} artifacts={report['artifact_count']} signature={report['signature'].get('format')}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
