#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote


SCHEMA = "providapt.visual_regression_snapshots.v1"
DEFAULT_VIEWPORTS = ["390x844", "1366x768", "1920x1080", "2560x1080"]
DEFAULT_DASHBOARD_ASSERTIONS = {
    "max_horizontal_overflow_px": 2,
    "max_element_overflow_px": 2,
    "max_text_overflow_px": 2,
}


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


def viewport_class(viewport: dict[str, Any]) -> str:
    width = int(viewport.get("width") or 0)
    height = int(viewport.get("height") or 0)
    if width < 768:
        return "mobile"
    if width >= 2400 and width > height * 2:
        return "ultrawide"
    if width >= 1900:
        return "desktop_1080p"
    return "desktop_1366"


def attach_coverage_summary(report: dict[str, Any]) -> None:
    screenshots = report.get("screenshots", [])
    screenshot_index = {
        (
            str(shot.get("page", "")),
            str((shot.get("viewport") or {}).get("name", "")),
        ): shot
        for shot in screenshots
        if isinstance(shot, dict)
    }
    pages = sorted({str(shot.get("page", "")) for shot in screenshots if shot.get("page")})
    viewports = sorted({str((shot.get("viewport") or {}).get("name", "")) for shot in screenshots if (shot.get("viewport") or {}).get("name")})
    classes = sorted({viewport_class(shot.get("viewport") or {}) for shot in screenshots})
    expected_pages = {"dashboard", "trace-viewer"}
    expected_viewports = set(DEFAULT_VIEWPORTS)
    captured = [shot for shot in screenshots if shot.get("status") in {"captured", "planned"}]
    required_matrix = []
    for page in sorted(expected_pages):
        for viewport in sorted(expected_viewports):
            shot = screenshot_index.get((page, viewport), {})
            required_matrix.append(
                {
                    "page": page,
                    "viewport": viewport,
                    "status": str(shot.get("status") or "missing"),
                    "path": str(shot.get("path") or ""),
                    "present": bool(shot),
                    "has_dom_assertions": isinstance(shot.get("dom_assertions"), dict),
                    "has_hash": bool(shot.get("sha256")),
                }
            )
    report["coverage"] = {
        "pages": pages,
        "viewports": viewports,
        "viewport_classes": classes,
        "screenshot_count": len(screenshots),
        "covered_count": len(captured),
        "missing_pages": sorted(expected_pages - set(pages)),
        "missing_default_viewports": sorted(expected_viewports - set(viewports)),
        "complete_default_matrix": not (expected_pages - set(pages)) and not (expected_viewports - set(viewports)),
        "required_matrix": required_matrix,
    }


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
    report = {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "planned" if args.dry_run else "pending",
        "server": args.server,
        "alert_id": args.alert_id,
        "screenshots": screenshots,
        "failures": [],
        "warnings": [],
        "capture_diagnostics": capture_diagnostics(args),
    }
    attach_coverage_summary(report)
    return report


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
        f"- Coverage: `{report.get('coverage', {}).get('covered_count', 0)}/{report.get('coverage', {}).get('screenshot_count', 0)}`",
        f"- Viewport classes: `{', '.join(report.get('coverage', {}).get('viewport_classes', []))}`",
        "",
        "| Page | Viewport | Status | Path |",
        "| --- | --- | --- | --- |",
    ]
    diagnostics = report.get("capture_diagnostics") if isinstance(report.get("capture_diagnostics"), dict) else {}
    if diagnostics:
        lines[7:7] = [
            f"- Playwright available: `{str(diagnostics.get('playwright_available', False)).lower()}`",
            f"- Control plane access: `{diagnostics.get('control_plane_access', 'open-source')}`",
            f"- Capture mode: `{diagnostics.get('mode', 'unknown')}`",
        ]
    comparison = report.get("comparison_summary") if isinstance(report.get("comparison_summary"), dict) else {}
    if comparison:
        counts = comparison.get("counts") if isinstance(comparison.get("counts"), dict) else {}
        lines[8:8] = [
            f"- Baseline comparison: `changed={counts.get('changed', 0)} / unchanged={counts.get('unchanged', 0)} / new={counts.get('new', 0)} / skipped={counts.get('skipped', 0)}`",
            f"- Baseline status: `{comparison.get('status', 'unknown')}`",
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
    if comparison:
        lines.extend(["", "## Baseline Summary", "", "| Status | Count |", "| --- | ---: |"])
        for status, count in sorted((comparison.get("counts") or {}).items()):
            lines.append(f"| {status} | {count} |")
        for key, title in [
            ("changed", "Changed Screenshots"),
            ("new", "New Screenshots"),
            ("skipped", "Skipped Comparisons"),
        ]:
            items = comparison.get(key) or []
            if items:
                lines.extend(["", f"### {title}"])
                lines.extend(f"- {item['page']} {item['viewport']}: {item.get('detail', '')}" for item in items)
    coverage = report.get("coverage") or {}
    if coverage.get("required_matrix"):
        lines.extend(["", "## Required Matrix", "", "| Page | Viewport | Status | DOM | Hash | Path |", "| --- | --- | --- | --- | --- | --- |"])
        for item in coverage["required_matrix"]:
            lines.append(
                f"| {item['page']} | {item['viewport']} | {item['status']} | "
                f"{str(item.get('has_dom_assertions', False)).lower()} | "
                f"{str(item.get('has_hash', False)).lower()} | `{item.get('path', '')}` |"
            )
    if coverage.get("missing_pages") or coverage.get("missing_default_viewports"):
        lines.extend(["", "## Coverage Gaps"])
        if coverage.get("missing_pages"):
            lines.append(f"- Missing pages: `{', '.join(coverage['missing_pages'])}`")
        if coverage.get("missing_default_viewports"):
            lines.append(f"- Missing default viewports: `{', '.join(coverage['missing_default_viewports'])}`")
    (out_dir / "visual-regression-snapshots.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def promote_baseline(report: dict[str, Any], baseline_dir_value: str) -> dict[str, Any]:
    if not baseline_dir_value:
        return {}
    baseline_dir = Path(baseline_dir_value)
    promotion = {
        "status": "skipped",
        "baseline_dir": str(baseline_dir),
        "manifest": "",
        "promoted_count": 0,
        "failures": [],
    }
    if report.get("status") != "pass":
        promotion["status"] = "blocked"
        promotion["failures"].append(f"snapshot status must be pass before promotion, got {report.get('status')}")
        report.setdefault("failures", []).append("baseline promotion blocked: snapshot status is not pass")
        report["baseline_promotion"] = promotion
        report["status"] = "blocked"
        return promotion

    baseline_dir.mkdir(parents=True, exist_ok=True)
    promoted_report = json.loads(json.dumps(report))
    promoted_report["baseline_promoted_at"] = utc_now()
    promoted_report["baseline_source_server"] = report.get("server", "")
    promoted_report["baseline_source_alert_id"] = report.get("alert_id", "")
    promoted_report.pop("baseline_promotion", None)
    promoted_screenshots: list[dict[str, Any]] = []
    failures: list[str] = []
    for shot in promoted_report.get("screenshots", []):
        if shot.get("status") != "captured":
            failures.append(f"{shot.get('page')} {((shot.get('viewport') or {}).get('name'))}: screenshot was not captured")
            continue
        source = Path(str(shot.get("path") or ""))
        if not source.exists():
            failures.append(f"{shot.get('page')} {((shot.get('viewport') or {}).get('name'))}: screenshot file missing")
            continue
        target = baseline_dir / source.name
        shutil.copy2(source, target)
        updated = dict(shot)
        updated["path"] = str(target)
        inventory = file_inventory(str(target))
        if inventory.get("exists"):
            updated.update({"bytes": inventory["bytes"], "sha256": inventory["sha256"]})
        promoted_screenshots.append(updated)

    promoted_report["screenshots"] = promoted_screenshots
    attach_coverage_summary(promoted_report)
    manifest_path = baseline_dir / "visual-regression-snapshots.json"
    promoted_report["status"] = "pass" if not failures else "blocked"
    promoted_report["baseline_manifest"] = str(manifest_path)
    manifest_path.write_text(json.dumps(promoted_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    promotion.update(
        {
            "status": promoted_report["status"],
            "manifest": str(manifest_path),
            "promoted_count": len(promoted_screenshots),
            "failures": failures,
        }
    )
    report["baseline_promotion"] = promotion
    if failures:
        report.setdefault("failures", []).extend(f"baseline promotion: {failure}" for failure in failures)
        report["status"] = "blocked"
    return promotion


def capture(report: dict[str, Any], timeout_ms: int) -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit("Playwright is not installed. Install with: python3 -m pip install playwright && python3 -m playwright install chromium") from exc

    failures: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            for shot in report["screenshots"]:
                viewport = shot["viewport"]
                page = browser.new_page(
                    viewport={"width": viewport["width"], "height": viewport["height"]},
                )
                try:
                    page.goto(shot["url"], wait_until="networkidle", timeout=timeout_ms)
                    if shot["page"] == "dashboard":
                        shot["dom_assertions"] = dashboard_dom_assertions(page)
                        if shot["dom_assertions"].get("status") != "pass":
                            viewport_name = str((shot.get("viewport") or {}).get("name", "viewport"))
                            failures.append(
                                f"dashboard {viewport_name}: DOM overflow assertions failed "
                                f"(horizontal={shot['dom_assertions'].get('horizontal_overflow_px')}, "
                                f"element={shot['dom_assertions'].get('max_element_overflow_px')}, "
                                f"text={shot['dom_assertions'].get('max_text_overflow_px')})"
                            )
                    if shot["page"] == "trace-viewer":
                        shot["dom_assertions"] = trace_viewer_dom_assertions(page)
                        if shot["dom_assertions"].get("status") != "pass":
                            viewport_name = str((shot.get("viewport") or {}).get("name", "viewport"))
                            failures.append(f"trace-viewer {viewport_name}: DOM assertions failed ({', '.join(shot['dom_assertions'].get('failures', []))})")
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


def capture_diagnostics(args: argparse.Namespace) -> dict[str, Any]:
    playwright_available = importlib.util.find_spec("playwright") is not None
    return {
        "mode": "dry-run" if args.dry_run else "capture",
        "server": args.server,
        "alert_id": args.alert_id,
        "control_plane_access": "open-source",
        "playwright_available": playwright_available,
        "playwright_install_hint": "" if playwright_available else "python3 -m pip install playwright && python3 -m playwright install chromium",
        "default_viewports": DEFAULT_VIEWPORTS,
        "requested_viewports": [str(item.get("name") or "") for item in args.viewports],
        "timeout_ms": args.timeout_ms,
    }


def dashboard_dom_assertions(page: Any) -> dict[str, Any]:
    script = """
    () => {
      const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
      const body = document.body;
      const root = document.documentElement;
      const scrollWidth = Math.max(body ? body.scrollWidth : 0, root ? root.scrollWidth : 0);
      const horizontalOverflowPx = Math.max(0, scrollWidth - viewportWidth);
      const elementOverflows = [];
      const textOverflows = [];
      const ignored = new Set(['SCRIPT', 'STYLE', 'META', 'LINK', 'TITLE']);
      document.querySelectorAll('body *').forEach((el) => {
        if (!el || ignored.has(el.tagName) || el.hidden) return;
        const style = window.getComputedStyle(el);
        if (!style || style.display === 'none' || style.visibility === 'hidden') return;
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return;
        const leftOverflow = Math.max(0, -rect.left);
        const rightOverflow = Math.max(0, rect.right - viewportWidth);
        const overflowPx = Math.max(leftOverflow, rightOverflow);
        if (overflowPx > 2 && style.position !== 'fixed') {
          elementOverflows.push({
            selector: el.id ? '#' + el.id : (el.className ? String(el.tagName).toLowerCase() + '.' + String(el.className).trim().split(/\\s+/).slice(0, 3).join('.') : String(el.tagName).toLowerCase()),
            overflow_px: Math.round(overflowPx),
            text: (el.textContent || '').trim().slice(0, 80)
          });
        }
        const textOverflowPx = Math.max(0, el.scrollWidth - el.clientWidth);
        if (textOverflowPx > 2 && rect.width > 0 && style.overflowX !== 'auto' && style.overflowX !== 'scroll') {
          const text = (el.textContent || '').replace(/\\s+/g, ' ').trim();
          if (text.length > 0) {
            textOverflows.push({
              selector: el.id ? '#' + el.id : String(el.tagName).toLowerCase(),
              overflow_px: Math.round(textOverflowPx),
              text: text.slice(0, 80)
            });
          }
        }
      });
      return {
        viewport_width: viewportWidth,
        scroll_width: scrollWidth,
        horizontal_overflow_px: Math.round(horizontalOverflowPx),
        element_overflows: elementOverflows.slice(0, 20),
        text_overflows: textOverflows.slice(0, 20)
      };
    }
    """
    result = page.evaluate(script)
    result = result if isinstance(result, dict) else {}
    horizontal = int(result.get("horizontal_overflow_px") or 0)
    element_max = max([int(item.get("overflow_px") or 0) for item in result.get("element_overflows", [])] or [0])
    text_max = max([int(item.get("overflow_px") or 0) for item in result.get("text_overflows", [])] or [0])
    thresholds = dict(DEFAULT_DASHBOARD_ASSERTIONS)
    passed = (
        horizontal <= thresholds["max_horizontal_overflow_px"]
        and element_max <= thresholds["max_element_overflow_px"]
        and text_max <= thresholds["max_text_overflow_px"]
    )
    result.update(
        {
            "status": "pass" if passed else "fail",
            "thresholds": thresholds,
            "max_element_overflow_px": element_max,
            "max_text_overflow_px": text_max,
        }
    )
    return result


def trace_viewer_dom_assertions(page: Any) -> dict[str, Any]:
    script = """
    () => {
      const text = document.body ? document.body.innerText : '';
      const layoutModes = Array.from(document.querySelectorAll('[data-layout-mode]')).map(el => el.getAttribute('data-layout-mode'));
      const buttons = Array.from(document.querySelectorAll('button, a.tool-link')).map(el => (el.textContent || '').trim());
      const svg = document.querySelector('#canvas svg');
      return {
        has_svg: Boolean(svg),
        svg_width: svg ? Number(svg.getAttribute('width') || 0) : 0,
        svg_height: svg ? Number(svg.getAttribute('height') || 0) : 0,
        layout_modes: layoutModes,
        has_png_export: buttons.includes('PNG'),
        has_svg_export: buttons.includes('SVG'),
        has_raw_svg: buttons.includes('Raw SVG'),
        has_report_export: buttons.includes('Report'),
        has_summary: text.includes('Trace Summary'),
        has_selected_panel: text.includes('Selected Element')
      };
    }
    """
    result = page.evaluate(script)
    result = result if isinstance(result, dict) else {}
    failures: list[str] = []
    if not result.get("has_svg"):
        failures.append("svg missing")
    if int(result.get("svg_width") or 0) <= 0 or int(result.get("svg_height") or 0) <= 0:
        failures.append("svg dimensions missing")
    modes = set(result.get("layout_modes") or [])
    missing_modes = sorted({"tree", "compact", "timeline", "grouped"} - modes)
    if missing_modes:
        failures.append("layout modes missing: " + ",".join(missing_modes))
    for key, label in [
        ("has_png_export", "PNG export missing"),
        ("has_svg_export", "SVG export missing"),
        ("has_raw_svg", "raw SVG link missing"),
        ("has_report_export", "report export missing"),
        ("has_summary", "summary panel missing"),
        ("has_selected_panel", "selected panel missing"),
    ]:
        if not result.get(key):
            failures.append(label)
    result["failures"] = failures
    result["status"] = "pass" if not failures else "fail"
    return result


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
        report["comparison_summary"] = {
            "status": "missing_baseline",
            "baseline_path": baseline_path,
            "counts": {"missing_baseline": 1},
            "changed": [],
            "new": [],
            "skipped": [],
        }
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
    report["comparison_summary"] = comparison_summary(comparisons, baseline_path)
    if any(item["status"] == "changed" for item in comparisons) and report.get("status") == "pass":
        report["status"] = "warn"
    attach_coverage_summary(report)


def comparison_summary(comparisons: list[dict[str, str]], baseline_path: str = "") -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in comparisons:
        status = str(item.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    changed = [item for item in comparisons if item.get("status") == "changed"]
    new = [item for item in comparisons if item.get("status") == "new"]
    skipped = [item for item in comparisons if item.get("status") == "skipped"]
    if changed:
        status = "changed"
    elif skipped:
        status = "incomplete"
    elif new:
        status = "expanded"
    else:
        status = "matched"
    return {
        "status": status,
        "baseline_path": baseline_path,
        "counts": dict(sorted(counts.items())),
        "changed": changed,
        "new": new,
        "skipped": skipped,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture dashboard and trace viewer screenshots for visual regression review.")
    parser.add_argument("--server", required=True, help="ProvidAPT base URL, for example http://127.0.0.1:18080")
    parser.add_argument("--alert-id", default="p:100")
    parser.add_argument("--out-dir", default="build/visual-regression")
    parser.add_argument("--baseline", default="", help="Existing visual-regression-snapshots.json to compare against")
    parser.add_argument("--promote-baseline", default="", help="Directory where passing captured screenshots should be copied as a new baseline")
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
        try:
            report = capture(report, args.timeout_ms)
        except SystemExit as exc:
            message = str(exc)
            report["status"] = "blocked"
            report.setdefault("failures", []).append(message)
            report["capture_diagnostics"] = capture_diagnostics(args)
    attach_inventory(report)
    attach_coverage_summary(report)
    compare_baseline(report, args.baseline)
    promote_baseline(report, args.promote_baseline)
    write_outputs(report, Path(args.out_dir))
    print(f"status={report['status']} screenshots={len(report['screenshots'])} out_dir={args.out_dir}")
    return 0 if report["status"] in {"pass", "planned"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
