#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.release_final_plan.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def step(step_id: str, title: str, command: str, evidence: list[str]) -> dict[str, Any]:
    return {
        "id": step_id,
        "title": title,
        "command": command,
        "evidence": evidence,
    }


def build_plan(args: argparse.Namespace) -> dict[str, Any]:
    version = args.version or args.release_tag
    evidence_doc = args.evidence_doc or f"docs/project/release-evidence-{version}.md"
    dist_dir = args.dist_dir or "dist"
    security_dir = args.security_dir or "build/security"
    steps = [
        step(
            "github_actions_evidence",
            "Archive final CI evidence",
            f"make github-actions-evidence RELEASE_EVIDENCE={evidence_doc}",
            ["build/ci/github-actions-evidence.json", "build/ci/github-actions-evidence.md"],
        ),
        step(
            "release_security_scans",
            "Run local release security scans",
            f"make release-security-local-gate VERSION={version} SECURITY_DIR={security_dir}",
            [f"{security_dir}/release-security-local-gate.json"],
        ),
        step(
            "security_scan_manifest",
            "Build scanner manifest",
            f"make security-scan-manifest VERSION={version} SECURITY_DIR={security_dir}",
            [f"{security_dir}/scan-manifest.json"],
        ),
        step(
            "open_source_release_artifacts",
            "Build dist, SBOM, checksums, and readiness report",
            f"make release-open-source VERSION={version} DIST_DIR={dist_dir}",
            [dist_dir, f"{dist_dir}/checksums.txt", f"{dist_dir}/sbom.spdx.json", f"{dist_dir}/sbom.cdx.json"],
        ),
        step(
            "artifact_signing_gate",
            "Validate artifact signatures and checksums",
            f"make artifact-signing-gate DIST_DIR={dist_dir}",
            ["build/artifact-signing/artifact-signing-gate.json"],
        ),
        step(
            "release_evidence_manifest",
            "Index release evidence after artifacts are produced",
            f"make release-evidence-manifest EVIDENCE_PATHS=\"{evidence_doc} build {dist_dir}\"",
            ["build/release-evidence/evidence-manifest.json"],
        ),
        step(
            "release_evidence_consistency_gate",
            "Verify release evidence commit and artifact consistency",
            f"make release-evidence-consistency-gate VERSION={version} DIST_DIR={dist_dir}",
            ["build/release-evidence/release-evidence-consistency-gate.json"],
        ),
        step(
            "operator_release_gate",
            "Aggregate final release blockers",
            "make operator-release-gate",
            ["build/operator-release/operator-release-gate.json"],
        ),
        step(
            "tag_final_release",
            "Create final tag after evidence exists",
            f"git tag -a {args.release_tag} -m \"ProvidAPT {args.release_tag}\"",
            [args.release_tag],
        ),
        step(
            "publish_github_release",
            "Publish checked artifacts",
            f"make github-release RELEASE_TAG={args.release_tag} DIST_DIR={dist_dir}",
            [f"https://github.com/Chaoqun-Guo/ProvidAPT/releases/tag/{args.release_tag}"],
        ),
    ]
    if args.skip_push:
        steps[-1]["command"] = "skipped: push/publish disabled by --skip-push"
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "planned",
        "version": version,
        "release_tag": args.release_tag,
        "commit": args.commit,
        "dry_run": args.dry_run,
        "evidence_doc": evidence_doc,
        "steps": steps,
        "notes": [
            "Generate and commit evidence before creating the final tag.",
            "Do not include secrets, VM passwords, or private tailnet names in evidence artifacts.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Release Final Plan",
        "",
        f"- Status: `{report['status']}`",
        f"- Version: `{report['version']}`",
        f"- Release tag: `{report['release_tag']}`",
        f"- Evidence doc: `{report['evidence_doc']}`",
        "",
        "## Steps",
        "",
        "| Order | Step | Command | Evidence |",
        "| ---: | --- | --- | --- |",
    ]
    for index, item in enumerate(report["steps"], 1):
        lines.append(f"| {index} | {item['id']} | `{item['command']}` | {', '.join(item['evidence'])} |")
    lines.extend(["", "## Notes", ""])
    lines.extend(f"- {note}" for note in report["notes"])
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate an ordered final open-source release plan.")
    parser.add_argument("--version", default="")
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--evidence-doc", default="")
    parser.add_argument("--dist-dir", default="dist")
    parser.add_argument("--security-dir", default="build/security")
    parser.add_argument("--commit", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-push", action="store_true")
    parser.add_argument("--out-json", default="build/release-final/release-final-plan.json")
    parser.add_argument("--out-md", default="build/release-final/release-final-plan.md")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_plan(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"release final plan: status={report['status']} tag={report['release_tag']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
