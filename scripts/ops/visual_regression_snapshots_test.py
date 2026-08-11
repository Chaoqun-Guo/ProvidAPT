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
        self.assertIn("svg missing", result["failures"])
        self.assertIn("layout modes missing: compact,grouped,timeline", result["failures"])

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
            self.assertEqual(len(manifest["screenshots"]), 2)
            self.assertTrue(any("/dashboard" in item["url"] for item in manifest["screenshots"]))
            self.assertTrue(any("/api/v1/alerts/p%3A100/svg/view" in item["url"] for item in manifest["screenshots"]))
            self.assertEqual(manifest["coverage"]["covered_count"], 2)
            self.assertEqual(manifest["coverage"]["viewport_classes"], ["desktop_1366"])
            self.assertIn("1920x1080", manifest["coverage"]["missing_default_viewports"])

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


if __name__ == "__main__":
    unittest.main()
