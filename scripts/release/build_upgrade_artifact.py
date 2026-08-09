#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.upgrade_artifact.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_artifact(source: Path, out_dir: Path) -> Path:
    if not source.exists() or not source.is_file():
        raise SystemExit(f"{source}: artifact file does not exist")
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / source.name
    if source.resolve() != target.resolve():
        shutil.copy2(source, target)
    return target


def normalize_base_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise SystemExit("--base-url is required")
    return value.rstrip("/")


def write_outputs(args: argparse.Namespace) -> dict[str, Any]:
    artifact = copy_artifact(Path(args.artifact), Path(args.out_dir))
    checksum = sha256_file(artifact)
    base_url = normalize_base_url(args.base_url)
    download_url = f"{base_url}/{artifact.name}"
    signature_path = artifact.with_suffix(artifact.suffix + ".sig")
    signature_url = ""
    signature_algorithm = ""
    if args.signing_key:
        signature = hmac.new(args.signing_key.encode("utf-8"), checksum.encode("utf-8"), hashlib.sha256).hexdigest()
        signature_path.write_text(signature + "\n", encoding="utf-8")
        signature_url = f"{download_url}.sig"
        signature_algorithm = "hmac-sha256-of-package-sha256"
    elif signature_path.exists():
        signature_url = f"{download_url}.sig"
        signature_algorithm = "external"

    checksum_path = artifact.with_suffix(artifact.suffix + ".sha256")
    checksum_path.write_text(f"{checksum}  {artifact.name}\n", encoding="utf-8")
    manifest = {
        "schema": SCHEMA,
        "version": args.version,
        "download_url": download_url,
        "expected_sha256": checksum,
        "signature_url": signature_url,
        "signature_algorithm": signature_algorithm,
        "release_notes": args.release_notes or "",
        "published_at": args.published_at or utc_now(),
        "minimum_version": args.minimum_version or "",
        "artifact": {
            "name": artifact.name,
            "size_bytes": artifact.stat().st_size,
            "path": str(artifact),
            "sha256_path": str(checksum_path),
            "signature_path": str(signature_path) if signature_url else "",
        },
    }
    latest_path = artifact.parent / "latest.json"
    evidence_path = artifact.parent / "upgrade-artifact.md"
    latest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    evidence_path.write_text(render_markdown(manifest), encoding="utf-8")
    return manifest


def render_markdown(manifest: dict[str, Any]) -> str:
    artifact = manifest["artifact"]
    lines = [
        "# ProvidAPT Upgrade Artifact",
        "",
        f"- Version: `{manifest['version']}`",
        f"- Published at: `{manifest['published_at']}`",
        f"- Download URL: `{manifest['download_url']}`",
        f"- SHA256: `{manifest['expected_sha256']}`",
        f"- Signature URL: `{manifest.get('signature_url', '')}`",
        f"- Signature algorithm: `{manifest.get('signature_algorithm', '')}`",
        f"- Artifact path: `{artifact['path']}`",
        f"- Size bytes: `{artifact['size_bytes']}`",
        "",
        "## Operator Wiring",
        "",
        "- Set `PROVIDAPT_UPGRADE_DOWNLOAD_URL` to the download URL.",
        "- Set `PROVIDAPT_UPGRADE_SHA256` to the SHA256 value.",
        "- Set `PROVIDAPT_UPGRADE_SIGNATURE_URL` when the signature file is published.",
        "- Set `PROVIDAPT_UPGRADE_SIGNING_KEY` on agents when HMAC signatures are used.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a ProvidAPT upgrade artifact manifest, checksum, and optional HMAC signature.")
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--out-dir", default="build/upgrade-artifacts")
    parser.add_argument("--minimum-version", default="")
    parser.add_argument("--release-notes", default="")
    parser.add_argument("--published-at", default="")
    parser.add_argument("--signing-key", default="")
    manifest = write_outputs(parser.parse_args())
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
