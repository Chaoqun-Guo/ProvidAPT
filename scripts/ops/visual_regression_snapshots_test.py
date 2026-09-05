import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("visual-regression-snapshots.py")


def load_module():
    spec = importlib.util.spec_from_file_location("visual_regression_snapshots", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class VisualRegressionSnapshotsTest(unittest.TestCase):
    def test_parse_viewport(self):
        mod = load_module()
        self.assertEqual(mod.parse_viewport("1366x768"), {"name": "1366x768", "width": 1366, "height": 768})
        with self.assertRaises(Exception):
            mod.parse_viewport("tiny")

    def test_default_dashboard_viewports_cover_target_resolutions(self):
        mod = load_module()
        self.assertEqual(mod.DEFAULT_VIEWPORTS, ["390x844", "1366x768", "1920x1080", "2560x1080"])
        self.assertEqual(mod.DEFAULT_DASHBOARD_ASSERTIONS["max_horizontal_overflow_px"], 2)

    def test_dashboard_dom_assertions_mark_overflow_failures(self):
        mod = load_module()

        class FakePage:
            def evaluate(self, _script):
                return {
                    "horizontal_overflow_px": 12,
                    "element_overflows": [{"overflow_px": 9, "selector": ".wide"}],
                    "text_overflows": [{"overflow_px": 7, "selector": ".label"}],
                }

        result = mod.dashboard_dom_assertions(FakePage())

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["max_element_overflow_px"], 9)
        self.assertEqual(result["max_text_overflow_px"], 7)

    def test_dashboard_dom_assertions_mark_view_menu_failures(self):
        mod = load_module()

        class FakePage:
            def evaluate(self, _script):
                return {
                    "horizontal_overflow_px": 0,
                    "element_overflows": [],
                    "text_overflows": [],
                    "view_menu_failures": ["view menu is covered by div.dashboard-shell"],
                }

        result = mod.dashboard_dom_assertions(FakePage())

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["view_menu_failures"], ["view menu is covered by div.dashboard-shell"])

    def test_trace_viewer_dom_assertions_require_svg_and_exports(self):
        mod = load_module()

        class FakePage:
            def evaluate(self, _script):
                return {
                    "has_svg": False,
                    "svg_width": 0,
                    "svg_height": 0,
                    "layout_modes": ["tree"],
                    "has_png_export": True,
                    "has_svg_export": True,
                    "has_raw_svg": False,
                    "has_report_export": True,
                    "has_summary": True,
                    "has_selected_panel": True,
                }

        result = mod.trace_viewer_dom_assertions(FakePage())

        self.assertEqual(result["status"], "fail")
        self.assertIn("trace rendering missing", result["failures"])
        self.assertIn("trace render dimensions missing", result["failures"])
        self.assertIn("layout modes missing: compact,grouped,timeline", result["failures"])

    def test_trace_viewer_dom_assertions_accept_raw_svg_fallback_iframe(self):
        mod = load_module()

        class FakePage:
            def evaluate(self, _script):
                return {
                    "has_svg": False,
                    "has_fallback_frame": True,
                    "render_mode": "fallback-iframe",
                    "render_width": 1180,
                    "render_height": 680,
                    "svg_width": 0,
                    "svg_height": 0,
                    "layout_modes": ["tree", "compact", "timeline", "grouped"],
                    "has_png_export": True,
                    "has_svg_export": True,
                    "has_raw_svg": True,
                    "has_report_export": True,
                    "has_summary": True,
                    "has_selected_panel": True,
                }

        result = mod.trace_viewer_dom_assertions(FakePage())

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["render_mode"], "fallback-iframe")
        self.assertEqual(result["failures"], [])

    def test_dry_run_writes_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--server",
                    "http://127.0.0.1:18080",
                    "--alert-id",
                    "p:100",
                    "--viewport",
                    "1366x768",
                    "--dry-run",
                    "--out-dir",
                    tmp,
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertIn("status=planned", result.stdout)
            manifest = json.loads((Path(tmp) / "visual-regression-snapshots.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], "providapt.visual_regression_snapshots.v1")
            self.assertEqual(manifest["status"], "planned")
            self.assertEqual(manifest["capture_diagnostics"]["mode"], "dry-run")
            self.assertEqual(manifest["capture_diagnostics"]["control_plane_access"], "open-source")
            self.assertEqual(len(manifest["screenshots"]), 2)
            self.assertTrue(any("/dashboard" in item["url"] for item in manifest["screenshots"]))
            self.assertTrue(any("/api/v1/alerts/p%3A100/svg/view" in item["url"] for item in manifest["screenshots"]))
            self.assertEqual(manifest["coverage"]["covered_count"], 2)
            self.assertEqual(manifest["coverage"]["viewport_classes"], ["desktop_1366"])
            self.assertIn("1920x1080", manifest["coverage"]["missing_default_viewports"])
            self.assertEqual(len(manifest["coverage"]["required_matrix"]), 8)
            matrix = {
                (item["page"], item["viewport"]): item
                for item in manifest["coverage"]["required_matrix"]
            }
            self.assertEqual(matrix[("dashboard", "1366x768")]["status"], "planned")
            self.assertEqual(matrix[("trace-viewer", "390x844")]["status"], "missing")
            rendered = (Path(tmp) / "visual-regression-snapshots.md").read_text(encoding="utf-8")
            self.assertIn("Required Matrix", rendered)
            self.assertIn("Playwright available", rendered)
            self.assertIn("| trace-viewer | 390x844 | missing |", rendered)

    def test_baseline_compare_marks_changed(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "current.png"
            previous = root / "previous.png"
            current.write_bytes(b"current")
            previous.write_bytes(b"previous")
            report = {
                "status": "pass",
                "server": "http://127.0.0.1:18080",
                "alert_id": "p:100",
                "warnings": [],
                "screenshots": [
                    {
                        "page": "dashboard",
                        "viewport": {"name": "1366x768"},
                        "path": str(current),
                        "status": "captured",
                    }
                ],
            }
            baseline = {
                "screenshots": [
                    {
                        "page": "dashboard",
                        "viewport": {"name": "1366x768"},
                        "path": str(previous),
                        "status": "captured",
                    }
                ]
            }
            mod.attach_inventory(report)
            mod.attach_inventory(baseline)
            baseline_path = root / "baseline.json"
            baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
            mod.compare_baseline(report, str(baseline_path))
            self.assertEqual(report["status"], "warn")
            self.assertEqual(report["comparisons"][0]["status"], "changed")
            self.assertEqual(report["comparison_summary"]["status"], "changed")
            self.assertEqual(report["comparison_summary"]["counts"]["changed"], 1)
            mod.write_outputs(report, root)
            rendered = (root / "visual-regression-snapshots.md").read_text(encoding="utf-8")
            self.assertIn("Baseline Summary", rendered)
            self.assertIn("Changed Screenshots", rendered)

    def test_baseline_compare_records_missing_baseline_summary(self):
        mod = load_module()
        report = {"status": "pass", "warnings": [], "screenshots": []}
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "missing-baseline.json")
            mod.compare_baseline(report, missing)
            self.assertEqual(report["comparison_summary"]["status"], "missing_baseline")
            self.assertEqual(report["comparison_summary"]["counts"]["missing_baseline"], 1)
            self.assertIn("baseline manifest not found", report["warnings"][0])

    def test_promote_baseline_copies_captured_screenshots(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_dir = root / "current"
            baseline_dir = root / "baseline"
            out_dir.mkdir()
            shot = out_dir / "dashboard-1366x768.png"
            shot.write_bytes(b"visual")
            report = {
                "status": "pass",
                "server": "http://127.0.0.1:18080",
                "alert_id": "p:100",
                "screenshots": [
                    {
                        "page": "dashboard",
                        "viewport": {"name": "1366x768", "width": 1366, "height": 768},
                        "path": str(shot),
                        "status": "captured",
                    }
                ],
                "failures": [],
                "warnings": [],
            }
            mod.attach_inventory(report)

            promotion = mod.promote_baseline(report, str(baseline_dir))

            self.assertEqual(promotion["status"], "pass")
            self.assertEqual(promotion["promoted_count"], 1)
            self.assertTrue((baseline_dir / "dashboard-1366x768.png").exists())
            baseline = json.loads((baseline_dir / "visual-regression-snapshots.json").read_text(encoding="utf-8"))
            self.assertEqual(baseline["status"], "pass")
            self.assertEqual(baseline["screenshots"][0]["path"], str(baseline_dir / "dashboard-1366x768.png"))
            self.assertEqual(baseline["screenshots"][0]["sha256"], report["screenshots"][0]["sha256"])
            self.assertEqual(report["baseline_promotion"]["manifest"], str(baseline_dir / "visual-regression-snapshots.json"))

    def test_promote_baseline_blocks_non_passing_report(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            report = {"status": "warn", "screenshots": [], "failures": [], "warnings": []}

            promotion = mod.promote_baseline(report, str(Path(tmp) / "baseline"))

            self.assertEqual(promotion["status"], "blocked")
            self.assertEqual(report["status"], "blocked")
            self.assertIn("baseline promotion blocked", report["failures"][0])

    def test_coverage_summary_marks_complete_default_matrix(self):
        mod = load_module()
        report = {
            "screenshots": [
                {
                    "page": page,
                    "viewport": mod.parse_viewport(viewport),
                    "status": "planned",
                    "path": f"{page}-{viewport}.png",
                }
                for page in ["dashboard", "trace-viewer"]
                for viewport in mod.DEFAULT_VIEWPORTS
            ]
        }
        mod.attach_coverage_summary(report)
        self.assertTrue(report["coverage"]["complete_default_matrix"])
        self.assertEqual(report["coverage"]["covered_count"], 8)
        self.assertIn("mobile", report["coverage"]["viewport_classes"])
        self.assertIn("ultrawide", report["coverage"]["viewport_classes"])
        self.assertTrue(all(item["present"] for item in report["coverage"]["required_matrix"]))


if __name__ == "__main__":
    unittest.main()
