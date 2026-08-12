#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.visual_regression_gate.v1"
TARGET_VIEWPORTS = {"390x844", "1366x768", "1920x1080", "2560x1080"}
TARGET_PAGES = {"dashboard", "trace-viewer"}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        raise SystemExit(f"missing visual regression manifest: {path}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def screenshot_key(item: dict[str, Any]) -> tuple[str, str]:
    viewport = item.get("viewport") if isinstance(item.get("viewport"), dict) else {}
    return str(item.get("page") or ""), str(viewport.get("name") or "")


def visual_evidence_summary(
    manifest: dict[str, Any],
    screenshots: list[dict[str, Any]],
    required_pages: set[str],
    required_viewports: set[str],
    missing_required: list[tuple[str, str]],
) -> dict[str, Any]:
    coverage = manifest.get("coverage") if isinstance(manifest.get("coverage"), dict) else {}
    comparison = manifest.get("comparison_summary") if isinstance(manifest.get("comparison_summary"), dict) else {}
    comparison_counts = comparison.get("counts") if isinstance(comparison.get("counts"), dict) else {}
    screenshot_status: dict[str, int] = {}
    page_status: dict[str, dict[str, int]] = {}
    dom_total = 0
    dom_failed = 0
    dom_missing = 0
    missing_by_page: dict[str, list[str]] = {}
    missing_by_viewport: dict[str, list[str]] = {}
    for page, viewport in missing_required:
        missing_by_page.setdefault(page, []).append(viewport)
        missing_by_viewport.setdefault(viewport, []).append(page)
    for item in screenshots:
        page, _viewport = screenshot_key(item)
        status = str(item.get("status") or "unknown")
        screenshot_status[status] = screenshot_status.get(status, 0) + 1
        page_status.setdefault(page or "unknown", {})
        page_status[page or "unknown"][status] = page_status[page or "unknown"].get(status, 0) + 1
        assertions = item.get("dom_assertions") if isinstance(item.get("dom_assertions"), dict) else {}
        if assertions:
            dom_total += 1
            if str(assertions.get("status") or "").lower() != "pass":
                dom_failed += 1
        else:
            dom_missing += 1
    return {
        "coverage": {
            "covered_count": coverage.get("covered_count", 0),
            "screenshot_count": coverage.get("screenshot_count", len(screenshots)),
            "complete_default_matrix": bool(coverage.get("complete_default_matrix")),
            "viewport_classes": list(coverage.get("viewport_classes") or []),
            "missing_pages": list(coverage.get("missing_pages") or []),
            "missing_default_viewports": list(coverage.get("missing_default_viewports") or []),
        },
        "required_matrix": {
            "pages": sorted(required_pages),
            "viewports": sorted(required_viewports),
            "missing": [{"page": page, "viewport": viewport} for page, viewport in missing_required],
            "missing_count": len(missing_required),
            "missing_by_page": {page: sorted(viewports) for page, viewports in sorted(missing_by_page.items())},
            "missing_by_viewport": {viewport: sorted(pages) for viewport, pages in sorted(missing_by_viewport.items())},
        },
        "screenshots": {
            "total": len(screenshots),
            "by_status": dict(sorted(screenshot_status.items())),
            "by_page": dict(sorted(page_status.items())),
        },
        "dom_assertions": {
            "total": dom_total,
            "failed": dom_failed,
            "missing": dom_missing,
        },
        "baseline": {
            "status": comparison.get("status", ""),
            "counts": dict(sorted(comparison_counts.items())),
            "changed": comparison_counts.get("changed", 0),
            "new": comparison_counts.get("new", 0),
            "skipped": comparison_counts.get("skipped", 0),
            "missing_baseline": comparison_counts.get("missing_baseline", 0),
        },
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    manifest_path = Path(args.manifest)
    manifest = load_json(manifest_path)
    failures: list[str] = []
    warnings: list[str] = []
    screenshots = [item for item in manifest.get("screenshots", []) if isinstance(item, dict)]
    seen = {screenshot_key(item) for item in screenshots}
    required_pages = set(args.required_page or TARGET_PAGES)
    required_viewports = set(args.required_viewport or TARGET_VIEWPORTS)
    missing_required: list[tuple[str, str]] = []
    for page in sorted(required_pages):
        for viewport in sorted(required_viewports):
            if (page, viewport) not in seen:
                missing_required.append((page, viewport))
                failures.append(f"missing screenshot: {page} {viewport}")
    for item in screenshots:
        page, viewport = screenshot_key(item)
        status = str(item.get("status") or "")
        path = Path(str(item.get("path") or ""))
        if page in required_pages and viewport in required_viewports:
            if args.require_captured and status != "captured":
                failures.append(f"{page} {viewport} status is {status or 'missing'}, expected captured")
            if args.require_files and (not path.exists() or path.stat().st_size == 0):
                failures.append(f"{page} {viewport} screenshot file is missing or empty: {path}")
            if args.require_hash and not item.get("sha256"):
                failures.append(f"{page} {viewport} screenshot hash is missing")
            assertions = item.get("dom_assertions") if isinstance(item.get("dom_assertions"), dict) else {}
            if args.require_dom_assertions and not assertions:
                failures.append(f"{page} {viewport} DOM assertions are missing")
            if assertions and assertions.get("status") != "pass":
                failures.append(f"{page} {viewport} DOM assertions failed")
    if manifest.get("failures"):
        failures.extend(str(item) for item in manifest.get("failures") or [])
    comparisons = [item for item in manifest.get("comparisons", []) if isinstance(item, dict)]
    changed = [item for item in comparisons if str(item.get("status")) == "changed"]
    skipped = [item for item in comparisons if str(item.get("status")) == "skipped"]
    if args.block_changed and changed:
        failures.extend(f"baseline changed: {item.get('page')} {item.get('viewport')}" for item in changed)
    elif changed:
        warnings.extend(f"baseline changed: {item.get('page')} {item.get('viewport')}" for item in changed)
    if skipped:
        warnings.extend(f"baseline comparison skipped: {item.get('page')} {item.get('viewport')} {item.get('detail', '')}" for item in skipped)
    if manifest.get("status") == "planned" and args.require_captured:
        failures.append("visual regression manifest is dry-run/planned, not captured")
    status = "blocked" if failures else "warn" if warnings else "pass"
    summary = visual_evidence_summary(manifest, screenshots, required_pages, required_viewports, missing_required)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "manifest": str(manifest_path),
        "required_pages": sorted(required_pages),
        "required_viewports": sorted(required_viewports),
        "screenshot_count": len(screenshots),
        "comparison_count": len(comparisons),
        "visual_evidence_summary": summary,
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Visual Regression Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Manifest: `{report['manifest']}`",
        f"- Screenshots: `{report['screenshot_count']}`",
        f"- Comparisons: `{report['comparison_count']}`",
        "",
        "## Evidence Summary",
        "",
        "| Area | Value |",
        "| --- | --- |",
        f"| Coverage | {report['visual_evidence_summary']['coverage']['covered_count']}/{report['visual_evidence_summary']['coverage']['screenshot_count']} |",
        f"| Complete matrix | {str(report['visual_evidence_summary']['coverage']['complete_default_matrix']).lower()} |",
        f"| Missing required screenshots | {report['visual_evidence_summary']['required_matrix']['missing_count']} |",
        f"| Baseline status | {report['visual_evidence_summary']['baseline']['status'] or 'none'} |",
        f"| Baseline counts | {json.dumps(report['visual_evidence_summary']['baseline']['counts'], sort_keys=True)} |",
        f"| DOM assertions | failed={report['visual_evidence_summary']['dom_assertions']['failed']} missing={report['visual_evidence_summary']['dom_assertions']['missing']} total={report['visual_evidence_summary']['dom_assertions']['total']} |",
        "",
        "| Required Page | Required Viewports |",
        "| --- | --- |",
    ]
    for page in report["required_pages"]:
        lines.append(f"| {page} | {', '.join(report['required_viewports'])} |")
    missing = report["visual_evidence_summary"]["required_matrix"].get("missing") or []
    if missing:
        lines.extend(["", "## Missing Required Matrix", "", "| Page | Viewport |", "| --- | --- |"])
        for item in missing:
            lines.append(f"| {item['page']} | {item['viewport']} |")
        missing_by_page = report["visual_evidence_summary"]["required_matrix"].get("missing_by_page") or {}
        if missing_by_page:
            lines.extend(["", "### Missing By Page"])
            for page, viewports in missing_by_page.items():
                lines.append(f"- `{page}`: {', '.join(viewports)}")
        missing_by_viewport = report["visual_evidence_summary"]["required_matrix"].get("missing_by_viewport") or {}
        if missing_by_viewport:
            lines.extend(["", "### Missing By Viewport"])
            for viewport, pages in missing_by_viewport.items():
                lines.append(f"- `{viewport}`: {', '.join(pages)}")
    if report["failures"]:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
    if report["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {item}" for item in report["warnings"])
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gate Dashboard and Trace Viewer visual regression screenshot evidence.")
    parser.add_argument("--manifest", default="build/visual-regression/visual-regression-snapshots.json")
    parser.add_argument("--required-page", action="append", default=[])
    parser.add_argument("--required-viewport", action="append", default=[])
    parser.add_argument("--allow-planned", action="store_true", help="Allow dry-run manifests for local planning only")
    parser.add_argument("--allow-missing-files", action="store_true")
    parser.add_argument("--allow-missing-hash", action="store_true")
    parser.add_argument("--allow-missing-dom-assertions", action="store_true")
    parser.add_argument("--warn-on-changed", action="store_true", help="Warn rather than block when baseline hashes differ")
    parser.add_argument("--out-json", default="build/visual-regression/visual-regression-gate.json")
    parser.add_argument("--out-md", default="build/visual-regression/visual-regression-gate.md")
    args = parser.parse_args(argv)
    args.require_captured = not args.allow_planned
    args.require_files = not args.allow_missing_files
    args.require_hash = not args.allow_missing_hash
    args.require_dom_assertions = not args.allow_missing_dom_assertions
    args.block_changed = not args.warn_on_changed
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"visual regression gate: status={report['status']} screenshots={report['screenshot_count']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
