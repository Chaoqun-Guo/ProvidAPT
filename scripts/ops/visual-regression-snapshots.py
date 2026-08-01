#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote


SCHEMA = "providapt.visual_regression_snapshots.v1"
DEFAULT_VIEWPORTS = ["1366x768", "1920x1080", "2560x1080"]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_viewport(value: str) -> dict[str, int | str]:
    parts = value.lower().split("x", 1)
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(f"invalid viewport {value!r}, expected WIDTHxHEIGHT")
    try:
        width = int(parts[0])
        height = int(parts[1])
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid viewport {value!r}, expected integers") from exc
    if width < 320 or height < 240:
        raise argparse.ArgumentTypeError(f"invalid viewport {value!r}, minimum is 320x240")
    return {"name": f"{width}x{height}", "width": width, "height": height}


def target_pages(server: str, alert_id: str) -> list[dict[str, str]]:
    base = server.rstrip("/")
    encoded_alert = quote(alert_id, safe="")
    return [
        {"name": "dashboard", "url": f"{base}/dashboard"},
        {"name": "trace-viewer", "url": f"{base}/api/v1/alerts/{encoded_alert}/svg/view"},
    ]


def planned_manifest(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = Path(args.out_dir)
    pages = target_pages(args.server, args.alert_id)
    screenshots: list[dict[str, Any]] = []
    for page in pages:
        for viewport in args.viewports:
            file_name = f"{page['name']}-{viewport['name']}.png"
            screenshots.append(
                {
                    "page": page["name"],
                    "url": page["url"],
                    "viewport": viewport,
                    "path": str(out_dir / file_name),
                    "status": "planned" if args.dry_run else "pending",
                }
            )
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "planned" if args.dry_run else "pending",
        "server": args.server,
        "alert_id": args.alert_id,
        "screenshots": screenshots,
        "failures": [],
        "warnings": [],
    }


def write_outputs(report: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "visual-regression-snapshots.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# Visual Regression Snapshots",
        "",
        f"- Status: `{report['status']}`",
        f"- Server: `{report['server']}`",
        f"- Alert ID: `{report['alert_id']}`",
        "",
        "| Page | Viewport | Status | Path |",
        "| --- | --- | --- | --- |",
    ]
    for shot in report["screenshots"]:
        lines.append(
            f"| {shot['page']} | {shot['viewport']['name']} | {shot['status']} | `{shot['path']}` |"
        )
    if report.get("failures"):
        lines.extend(["", "## Failures"])
        lines.extend(f"- {failure}" for failure in report["failures"])
    if report.get("warnings"):
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {warning}" for warning in report["warnings"])
    if report.get("comparisons"):
        lines.extend(["", "## Baseline Comparison", "", "| Page | Viewport | Status | Detail |", "| --- | --- | --- | --- |"])
        for item in report["comparisons"]:
            lines.append(f"| {item['page']} | {item['viewport']} | {item['status']} | {item.get('detail', '')} |")
    (out_dir / "visual-regression-snapshots.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def capture(report: dict[str, Any], api_key: str, timeout_ms: int) -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit("Playwright is not installed. Install with: python3 -m pip install playwright && python3 -m playwright install chromium") from exc

    failures: list[str] = []
    headers = {"X-API-Key": api_key} if api_key else {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            for shot in report["screenshots"]:
                viewport = shot["viewport"]
                page = browser.new_page(
                    viewport={"width": viewport["width"], "height": viewport["height"]},
                    extra_http_headers=headers,
                )
                try:
                    page.goto(shot["url"], wait_until="networkidle", timeout=timeout_ms)
                    page.screenshot(path=shot["path"], full_page=True)
                    shot["status"] = "captured"
                except Exception as exc:  # pragma: no cover - depends on live browser/server state
                    shot["status"] = "failed"
                    failures.append(f"{shot['page']} {viewport['name']}: {exc}")
                finally:
                    page.close()
        finally:
            browser.close()
    report["failures"] = failures
    report["status"] = "pass" if not failures else "blocked"
    return report


def file_inventory(path_value: str) -> dict[str, Any]:
    path = Path(path_value)
    if not path.exists() or not path.is_file():
        return {"exists": False, "path": path_value}
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "exists": True,
        "path": path_value,
        "bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def attach_inventory(report: dict[str, Any]) -> None:
    for shot in report.get("screenshots", []):
        if shot.get("status") in {"captured", "planned"}:
            inventory = file_inventory(str(shot.get("path", "")))
            if inventory.get("exists"):
                shot.update({"bytes": inventory["bytes"], "sha256": inventory["sha256"]})


def compare_baseline(report: dict[str, Any], baseline_path: str) -> None:
    if not baseline_path:
        return
    baseline_file = Path(baseline_path)
    if not baseline_file.exists():
        report.setdefault("warnings", []).append(f"baseline manifest not found: {baseline_path}")
        return
    baseline = json.loads(baseline_file.read_text(encoding="utf-8"))
    baseline_index: dict[tuple[str, str], dict[str, Any]] = {}
    for shot in baseline.get("screenshots", []):
        key = (str(shot.get("page", "")), str((shot.get("viewport") or {}).get("name", "")))
        baseline_index[key] = shot
    comparisons: list[dict[str, str]] = []
    for shot in report.get("screenshots", []):
        viewport = str((shot.get("viewport") or {}).get("name", ""))
        key = (str(shot.get("page", "")), viewport)
        previous = baseline_index.get(key)
        if not previous:
            comparisons.append({"page": key[0], "viewport": viewport, "status": "new", "detail": "no baseline screenshot"})
            continue
        current_hash = shot.get("sha256")
        previous_hash = previous.get("sha256")
        if not current_hash:
            comparisons.append({"page": key[0], "viewport": viewport, "status": "skipped", "detail": "current screenshot missing hash"})
        elif not previous_hash:
            comparisons.append({"page": key[0], "viewport": viewport, "status": "skipped", "detail": "baseline screenshot missing hash"})
        elif current_hash == previous_hash:
            comparisons.append({"page": key[0], "viewport": viewport, "status": "unchanged", "detail": "sha256 match"})
        else:
            comparisons.append({"page": key[0], "viewport": viewport, "status": "changed", "detail": "sha256 differs"})
    report["comparisons"] = comparisons
    if any(item["status"] == "changed" for item in comparisons) and report.get("status") == "pass":
        report["status"] = "warn"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture dashboard and trace viewer screenshots for visual regression review.")
    parser.add_argument("--server", required=True, help="ProvidAPT base URL, for example http://127.0.0.1:18080")
    parser.add_argument("--alert-id", default="p:100")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--out-dir", default="build/visual-regression")
    parser.add_argument("--baseline", default="", help="Existing visual-regression-snapshots.json to compare against")
    parser.add_argument("--viewport", action="append", type=parse_viewport, dest="viewports")
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not args.viewports:
        args.viewports = [parse_viewport(item) for item in DEFAULT_VIEWPORTS]
    return args


def main() -> int:
    args = parse_args()
    report = planned_manifest(args)
    if not args.dry_run:
        report = capture(report, args.api_key, args.timeout_ms)
    attach_inventory(report)
    compare_baseline(report, args.baseline)
    write_outputs(report, Path(args.out_dir))
    print(f"status={report['status']} screenshots={len(report['screenshots'])} out_dir={args.out_dir}")
    return 0 if report["status"] in {"pass", "planned"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
