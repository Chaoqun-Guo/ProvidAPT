#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.github_actions_evidence.v1"


def run(args: list[str], cwd: Path) -> tuple[int, str]:
    try:
        proc = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False, timeout=60)
    except FileNotFoundError:
        return 127, "command not found"
    except subprocess.TimeoutExpired as exc:
        return 124, ((exc.stdout or "") + (exc.stderr or "")).strip()
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def git_value(repo: Path, args: list[str]) -> str:
    code, output = run(["git", *args], repo)
    if code != 0:
        return ""
    return output.splitlines()[0].strip() if output else ""


def collect(repo: Path, limit: int) -> dict[str, Any]:
    full_commit = git_value(repo, ["rev-parse", "HEAD"])
    short_commit = git_value(repo, ["rev-parse", "--short", "HEAD"])
    auth_code, auth_output = run(["gh", "auth", "status"], repo)
    if auth_code != 0 or "not logged" in auth_output.lower():
        return {
            "schema": SCHEMA,
            "generated_at": now(),
            "status": "blocked",
            "commit": short_commit,
            "full_commit": full_commit,
            "runs": [],
            "failures": ["GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN"],
            "warnings": [],
        }
    code, output = run([
        "gh",
        "run",
        "list",
        "--limit",
        str(limit),
        "--json",
        "databaseId,headSha,status,conclusion,workflowName,createdAt,updatedAt,url",
    ], repo)
    if code != 0:
        return {
            "schema": SCHEMA,
            "generated_at": now(),
            "status": "blocked",
            "commit": short_commit,
            "full_commit": full_commit,
            "runs": [],
            "failures": [output or "gh run list failed"],
            "warnings": [],
        }
    runs = json.loads(output)
    matching = [run for run in runs if str(run.get("headSha", "")).startswith(full_commit)]
    if not matching:
        matching = [run for run in runs if str(run.get("headSha", "")).startswith(short_commit)]
    failures = [
        f"{run.get('workflowName')}: status={run.get('status')} conclusion={run.get('conclusion')}"
        for run in matching
        if run.get("status") != "completed" or run.get("conclusion") != "success"
    ]
    if not matching:
        failures.append(f"No GitHub Actions runs found for commit {full_commit}")
    return {
        "schema": SCHEMA,
        "generated_at": now(),
        "status": "pass" if not failures else "blocked",
        "commit": short_commit,
        "full_commit": full_commit,
        "runs": matching,
        "failures": failures,
        "warnings": [],
    }


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# GitHub Actions Evidence",
        "",
        f"- Status: `{report['status']}`",
        f"- Commit: `{report.get('full_commit', '')}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
        "| Workflow | Status | Conclusion | URL |",
        "| --- | --- | --- | --- |",
    ]
    for run_row in report.get("runs", []):
        lines.append(f"| {run_row.get('workflowName', '')} | {run_row.get('status', '')} | {run_row.get('conclusion', '')} | {run_row.get('url', '')} |")
    if report.get("failures"):
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
    lines.append("")
    return "\n".join(lines)


def archive_to_release_evidence(report: dict[str, Any], path: Path) -> None:
    start = "<!-- PROVIDAPT:GITHUB_ACTIONS_EVIDENCE:START -->"
    end = "<!-- PROVIDAPT:GITHUB_ACTIONS_EVIDENCE:END -->"
    section = "\n".join([
        start,
        "## GitHub Actions Final Evidence",
        "",
        f"- Status: `{report['status']}`",
        f"- Commit: `{report.get('full_commit', '')}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
        "| Workflow | Status | Conclusion | URL |",
        "| --- | --- | --- | --- |",
        *[
            f"| {run_row.get('workflowName', '')} | {run_row.get('status', '')} | {run_row.get('conclusion', '')} | {run_row.get('url', '')} |"
            for run_row in report.get("runs", [])
        ],
        end,
        "",
    ])
    existing = path.read_text(encoding="utf-8") if path.exists() else "# ProvidAPT Release Evidence\n\n"
    if start in existing and end in existing:
        before = existing.split(start, 1)[0].rstrip()
        after = existing.split(end, 1)[1].lstrip()
        updated = before + "\n\n" + section + after
    else:
        updated = existing.rstrip() + "\n\n" + section
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(updated, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect structured GitHub Actions evidence for the current commit.")
    parser.add_argument("--repo", default=".")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--out-json", default="build/ci/github-actions-evidence.json")
    parser.add_argument("--out-md", default="build/ci/github-actions-evidence.md")
    parser.add_argument("--release-evidence", default="", help="Append/update GitHub Actions evidence section in a release evidence Markdown file")
    args = parser.parse_args()
    report = collect(Path(args.repo).resolve(), args.limit)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    if args.release_evidence:
        archive_to_release_evidence(report, Path(args.release_evidence))
    print(f"status={report['status']} runs={len(report.get('runs', []))}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
