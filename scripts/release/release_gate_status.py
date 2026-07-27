#!/usr/bin/env python3
"""Collect commercial release gate status without requiring privileged tools."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


@dataclass
class Gate:
    name: str
    status: str
    message: str
    next_action: str = ""
    evidence: str = ""


def run_command(args: list[str], cwd: Path, timeout: int = 20) -> tuple[int, str]:
    try:
        proc = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return 127, "command not found"
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        return 124, output.strip() or "command timed out"
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output.strip()


def git_value(repo: Path, args: list[str], fallback: str = "unknown") -> str:
    code, output = run_command(["git", *args], repo)
    if code != 0 or not output:
        return fallback
    return output.splitlines()[0].strip()


def command_gate(command: str, package_hint: str) -> Gate:
    path = shutil.which(command)
    if path:
        return Gate(command, "available", f"{command} is available at {path}", evidence=path)
    return Gate(command, "blocked", f"{command} is not installed", f"Install {package_hint} or run this gate in approved CI")


def scan_evidence_gate(name: str, paths: Iterable[Path], next_action: str) -> Gate:
    present = [path for path in paths if path.exists() and path.stat().st_size > 0]
    if present:
        evidence = ", ".join(str(path) for path in present)
        return Gate(name, "pass", f"{name} evidence is present", evidence=evidence)
    expected = ", ".join(str(path) for path in paths)
    return Gate(name, "blocked", f"{name} evidence is missing: {expected}", next_action)


def text_mentions_gate(text: str, names: Iterable[str]) -> bool:
    lower = text.lower()
    decisions = ["approved", "approved_with_risk", "accepted", "waiver", "waived"]
    return any(name.lower() in lower for name in names) and any(decision in lower for decision in decisions)


def waiver_gate(name: str, waiver_paths: Iterable[Path], aliases: Iterable[str], blocked: Gate) -> Gate:
    for path in waiver_paths:
        if not path.exists() or path.stat().st_size == 0:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            if text_mentions_gate(text, aliases):
                return Gate(name, "waived", f"{name} is covered by waiver evidence", evidence=str(path))
            continue
        entries = data.get("waivers", data if isinstance(data, list) else [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            gate = str(entry.get("gate") or entry.get("name") or entry.get("id") or "")
            status = str(entry.get("status") or entry.get("decision") or "").lower()
            if gate.lower() in {alias.lower() for alias in aliases} and status in {"approved", "approved_with_risk", "accepted", "waived"}:
                return Gate(name, "waived", f"{name} is covered by structured waiver", evidence=str(path))
    return blocked


def ci_gate(repo: Path, commit: str, evidence_paths: Iterable[Path] = ()) -> Gate:
    for path in evidence_paths:
        if not path.exists() or path.stat().st_size == 0:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if commit in text and text_mentions_gate(text, ["github_actions", "github actions", "ci"]):
            return Gate("github_actions", "pass", "GitHub Actions evidence supplied by external record", evidence=str(path))
    if not shutil.which("gh"):
        return Gate("github_actions", "blocked", "GitHub CLI is not installed", "Install gh or attach GitHub Actions URLs manually")
    auth_code, auth_output = run_command(["gh", "auth", "status"], repo, timeout=15)
    if auth_code != 0:
        return Gate("github_actions", "blocked", "GitHub CLI is not authenticated", "Run gh auth login or set GH_TOKEN", auth_output)
    code, output = run_command(
        ["gh", "run", "list", "--limit", "10", "--json", "databaseId,headSha,status,conclusion,workflowName,url"],
        repo,
        timeout=30,
    )
    if code != 0:
        return Gate("github_actions", "blocked", "Unable to query GitHub Actions", "Attach Actions URLs manually", output)
    try:
        runs = json.loads(output)
    except json.JSONDecodeError:
        return Gate("github_actions", "blocked", "GitHub Actions output was not valid JSON", "Re-run gh run list", output[:500])
    matching = [run for run in runs if str(run.get("headSha", "")).startswith(commit)]
    if not matching:
        return Gate("github_actions", "blocked", f"No Actions run found for commit {commit}", "Wait for CI or attach run URL")
    failed = [run for run in matching if run.get("conclusion") not in ("success", None) or run.get("status") != "completed"]
    evidence = ", ".join(str(run.get("url", "")) for run in matching if run.get("url"))
    if failed:
        return Gate("github_actions", "fail", "One or more GitHub Actions runs are not successful", "Fix failing workflow and re-run", evidence)
    return Gate("github_actions", "pass", f"{len(matching)} GitHub Actions run(s) completed successfully", evidence=evidence)


def approval_gate(path: Path) -> Gate:
    if not path.exists():
        return Gate("external_approvals", "blocked", f"Approval record missing: {path}", "Create and sign commercial approval record")
    text = path.read_text(encoding="utf-8", errors="replace").lower()
    pending_markers = ["requires owner signoff", "requires approval", "external owner required", "pending", "not signed", "tbd", "blocked until"]
    if any(marker in text for marker in pending_markers):
        return Gate("external_approvals", "blocked", "Approval record still contains pending markers", "Record named decisions before release", str(path))
    return Gate("external_approvals", "pass", "Approval record has no obvious pending markers", evidence=str(path))


def artifact_gate(dist: Path, commit: str = "", version: str = "") -> Gate:
    checksums = dist / "checksums.txt"
    signature = dist / "checksums.txt.sig"
    sboms = list(dist.glob("*.spdx.json")) + list(dist.glob("*.cdx.json"))
    missing = [path for path in [checksums, signature] if not path.exists() or path.stat().st_size == 0]
    if missing or len(sboms) < 2:
        details = ", ".join(str(path) for path in missing) or "SBOM pair"
        return Gate("final_artifacts", "blocked", f"Final artifact evidence is incomplete: {details}", "Run make release-commercial from the final release commit")
    readiness = dist / "release-readiness.md"
    if readiness.exists():
        text = readiness.read_text(encoding="utf-8", errors="replace")
        if commit and commit not in text:
            return Gate("final_artifacts", "blocked", f"Release readiness evidence does not reference current commit {commit}", "Regenerate dist from the current release commit", str(readiness))
        if version and version not in text:
            return Gate("final_artifacts", "blocked", f"Release readiness evidence does not reference current version {version}", "Regenerate dist from the current release version", str(readiness))
    else:
        return Gate("final_artifacts", "blocked", f"Release readiness evidence missing: {readiness}", "Run make release-commercial from the final release commit")
    return Gate("final_artifacts", "pass", "Checksums, signature, SBOM, and current commit evidence are present", evidence=str(dist))


def collect(repo: Path, dist: Path, security_dir: Path, ci_evidence: Iterable[Path] = (), waiver_paths: Iterable[Path] = (), skip_ci: bool = False) -> dict[str, object]:
    commit = git_value(repo, ["rev-parse", "--short", "HEAD"])
    full_commit = git_value(repo, ["rev-parse", "HEAD"])
    version = git_value(repo, ["describe", "--tags", "--always"])
    govuln = scan_evidence_gate("govulncheck_evidence", [security_dir / "govulncheck.txt", security_dir / "govulncheck.json"], "Run govulncheck and store outputs under build/security")
    grype = scan_evidence_gate("grype_evidence", [security_dir / "grype-source.json"], "Run grype source scan or record a security waiver")
    trivy = scan_evidence_gate("trivy_evidence", [security_dir / "trivy-fs.json"], "Run trivy filesystem scan or record a security waiver")
    gates = [
        Gate("github_actions", "skipped", "GitHub Actions evidence intentionally skipped for this local P0 closure", evidence="--skip-ci")
        if skip_ci else ci_gate(repo, full_commit, ci_evidence),
        command_gate("govulncheck", "golang.org/x/vuln/cmd/govulncheck"),
        command_gate("grype", "anchore/grype"),
        command_gate("trivy", "aquasec/trivy"),
        waiver_gate("govulncheck_evidence", waiver_paths, ["govulncheck_evidence", "govulncheck"], govuln),
        waiver_gate("grype_evidence", waiver_paths, ["grype_evidence", "grype"], grype),
        waiver_gate("trivy_evidence", waiver_paths, ["trivy_evidence", "trivy"], trivy),
        approval_gate(repo / "docs/project/commercial-approval-record.md"),
        artifact_gate(dist, commit, version),
    ]
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": commit,
        "full_commit": full_commit,
        "version": version,
        "gates": [asdict(gate) for gate in gates],
    }


def render_markdown(report: dict[str, object]) -> str:
    rows = []
    for gate in report["gates"]:
        rows.append(
            "| {name} | {status} | {message} | {next_action} | {evidence} |".format(
                name=gate["name"],
                status=gate["status"],
                message=str(gate["message"]).replace("|", "\\|"),
                next_action=str(gate.get("next_action") or "").replace("|", "\\|"),
                evidence=str(gate.get("evidence") or "").replace("|", "\\|"),
            )
        )
    return "\n".join(
        [
            "# Release Gate Status",
            "",
            f"Generated: {report['generated_at']}",
            f"Commit: `{report['full_commit']}`",
            f"Version: `{report['version']}`",
            "",
            "| Gate | Status | Message | Next Action | Evidence |",
            "| --- | --- | --- | --- | --- |",
            *rows,
            "",
        ]
    )


def write_report(report: dict[str, object], markdown_path: Path, json_path: Path) -> None:
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository root")
    parser.add_argument("--dist", default="dist", help="Release artifact directory")
    parser.add_argument("--security-dir", default="build/security", help="Security scan evidence directory")
    parser.add_argument("--ci-evidence", action="append", default=[], help="External CI evidence file")
    parser.add_argument("--skip-ci", action="store_true", help="Skip GitHub Actions evidence for local release gate collection")
    parser.add_argument("--waiver", action="append", default=[], help="Structured JSON or Markdown waiver evidence")
    parser.add_argument("--out-md", default="build/release-gate-status.md", help="Markdown output path")
    parser.add_argument("--out-json", default="build/release-gate-status.json", help="JSON output path")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    report = collect(
        repo,
        (repo / args.dist).resolve(),
        (repo / args.security_dir).resolve(),
        [(repo / path).resolve() for path in args.ci_evidence],
        [(repo / path).resolve() for path in args.waiver],
        args.skip_ci,
    )
    write_report(report, repo / args.out_md, repo / args.out_json)
    blocked = [gate for gate in report["gates"] if gate["status"] in {"blocked", "fail"}]
    print(render_markdown(report))
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
