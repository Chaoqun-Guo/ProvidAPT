import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("visual-regression-gate.py")
SPEC = importlib.util.spec_from_file_location("visual_regression_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class VisualRegressionGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-visual-regression-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_manifest(self, screenshots, comparisons=None, status="pass"):
        path = self.tmp / "visual-regression-snapshots.json"
        path.write_text(
            json.dumps({
                "schema": "providapt.visual_regression_snapshots.v1",
                "status": status,
                "coverage": {
                    "covered_count": len(screenshots),
                    "screenshot_count": len(screenshots),
                    "complete_default_matrix": len(screenshots) == 8,
                    "viewport_classes": ["desktop_1366", "desktop_1080p", "mobile", "ultrawide"],
                },
                "comparison_summary": {
                    "status": "changed" if any(item.get("status") == "changed" for item in (comparisons or [])) else "matched",
                    "counts": {
                        "changed": sum(1 for item in (comparisons or []) if item.get("status") == "changed"),
                        "unchanged": sum(1 for item in (comparisons or []) if item.get("status") == "unchanged"),
                        "skipped": sum(1 for item in (comparisons or []) if item.get("status") == "skipped"),
                    },
                },
                "capture_diagnostics": {
                    "mode": "capture",
                    "server": "http://127.0.0.1:18080",
                    "api_key_supplied": True,
                    "playwright_available": True,
                    "requested_viewports": ["390x844", "1366x768", "1920x1080", "2560x1080"],
                },
                "screenshots": screenshots,
                "comparisons": comparisons or [],
                "failures": [],
            }),
            encoding="utf-8",
        )
        return path

    def shot(self, page, viewport):
        image = self.tmp / f"{page}-{viewport}.png"
        image.write_bytes(b"png")
        return {
            "page": page,
            "viewport": {"name": viewport, "width": 1366, "height": 768},
            "path": str(image),
            "status": "captured",
            "sha256": "a" * 64,
            "dom_assertions": {"status": "pass"},
        }

    def args(self, manifest, **overrides):
        values = {
            "manifest": str(manifest),
            "required_page": ["dashboard", "trace-viewer"],
            "required_viewport": ["390x844", "1366x768", "1920x1080", "2560x1080"],
            "require_captured": True,
            "require_files": True,
            "require_hash": True,
            "require_dom_assertions": True,
            "block_changed": True,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_passes_complete_captured_manifest(self):
        screenshots = [self.shot(page, viewport) for page in ["dashboard", "trace-viewer"] for viewport in ["390x844", "1366x768", "1920x1080", "2560x1080"]]
        report = subject.build_report(self.args(self.write_manifest(screenshots)))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["visual_evidence_summary"]["coverage"]["covered_count"], 8)
        self.assertTrue(report["visual_evidence_summary"]["capture_diagnostics"]["playwright_available"])
        self.assertEqual(report["visual_evidence_summary"]["dom_assertions"]["total"], 8)
        rendered = subject.render_markdown(report)
        self.assertIn("Evidence Summary", rendered)
        self.assertIn("Capture diagnostics", rendered)

    def test_blocks_missing_viewport(self):
        screenshots = [self.shot("dashboard", "1366x768")]
        report = subject.build_report(self.args(self.write_manifest(screenshots)))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("missing screenshot: trace-viewer 2560x1080", "\n".join(report["failures"]))
        self.assertIn("missing screenshot: dashboard 390x844", "\n".join(report["failures"]))
        self.assertGreater(report["visual_evidence_summary"]["required_matrix"]["missing_count"], 0)
        self.assertIn("390x844", report["visual_evidence_summary"]["required_matrix"]["missing_by_page"]["dashboard"])
        self.assertIn("trace-viewer", report["visual_evidence_summary"]["required_matrix"]["missing_by_viewport"]["2560x1080"])
        rendered = subject.render_markdown(report)
        self.assertIn("Missing Required Matrix", rendered)
        self.assertIn("Missing By Page", rendered)

    def test_blocks_changed_baseline_by_default(self):
        screenshots = [self.shot(page, viewport) for page in ["dashboard", "trace-viewer"] for viewport in ["390x844", "1366x768", "1920x1080", "2560x1080"]]
        manifest = self.write_manifest(screenshots, [{"page": "dashboard", "viewport": "1366x768", "status": "changed"}])
        report = subject.build_report(self.args(manifest))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["visual_evidence_summary"]["baseline"]["changed"], 1)

    def test_can_warn_on_changed_baseline(self):
        screenshots = [self.shot(page, viewport) for page in ["dashboard", "trace-viewer"] for viewport in ["390x844", "1366x768", "1920x1080", "2560x1080"]]
        manifest = self.write_manifest(screenshots, [{"page": "dashboard", "viewport": "1366x768", "status": "changed"}])
        report = subject.build_report(self.args(manifest, block_changed=False))
        self.assertEqual(report["status"], "warn")

    def test_blocks_failed_dom_assertions(self):
        screenshots = [self.shot(page, viewport) for page in ["dashboard", "trace-viewer"] for viewport in ["390x844", "1366x768", "1920x1080", "2560x1080"]]
        screenshots[0]["dom_assertions"] = {
            "status": "fail",
            "horizontal_overflow_px": 12,
            "max_element_overflow_px": 9,
            "max_text_overflow_px": 7,
            "element_overflows": [{"selector": ".wide", "overflow_px": 9}],
            "text_overflows": [{"selector": ".label", "overflow_px": 7}],
        }
        report = subject.build_report(self.args(self.write_manifest(screenshots)))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("DOM assertions failed", "\n".join(report["failures"]))
        self.assertEqual(report["visual_evidence_summary"]["dom_assertions"]["failed"], 1)
        details = report["visual_evidence_summary"]["dom_assertions"]["failure_details"]
        self.assertEqual(details[0]["page"], "dashboard")
        self.assertEqual(details[0]["horizontal_overflow_px"], 12)
        self.assertEqual(details[0]["element_overflow_examples"][0]["selector"], ".wide")
        rendered = subject.render_markdown(report)
        self.assertIn("DOM Failure Details", rendered)
        self.assertIn("horizontal=12", rendered)
        self.assertIn("element_examples=.wide", rendered)

    def test_summarizes_trace_viewer_dom_failure_details(self):
        screenshots = [self.shot(page, viewport) for page in ["dashboard", "trace-viewer"] for viewport in ["390x844", "1366x768", "1920x1080", "2560x1080"]]
        trace = next(item for item in screenshots if item["page"] == "trace-viewer" and item["viewport"]["name"] == "1366x768")
        trace["dom_assertions"] = {
            "status": "fail",
            "has_svg": False,
            "svg_width": 0,
            "svg_height": 0,
            "layout_modes": ["tree"],
            "has_png_export": False,
            "has_svg_export": True,
            "has_raw_svg": False,
            "has_report_export": True,
            "has_summary": True,
            "has_selected_panel": False,
            "failures": ["svg missing", "layout modes missing: compact,grouped,timeline"],
        }
        report = subject.build_report(self.args(self.write_manifest(screenshots)))
        self.assertEqual(report["status"], "blocked")
        details = report["visual_evidence_summary"]["dom_assertions"]["failure_details"]
        trace_detail = next(item for item in details if item["page"] == "trace-viewer")
        self.assertEqual(trace_detail["missing_layout_modes"], ["compact", "grouped", "timeline"])
        self.assertIn("PNG", trace_detail["missing_controls"])
        self.assertIn("Selected Element", trace_detail["missing_controls"])
        rendered = subject.render_markdown(report)
        self.assertIn("missing_layouts=compact,grouped,timeline", rendered)
        self.assertIn("missing_controls=PNG,Raw SVG,Selected Element", rendered)

    def test_blocks_missing_dom_assertions_by_default(self):
        screenshots = [self.shot(page, viewport) for page in ["dashboard", "trace-viewer"] for viewport in ["390x844", "1366x768", "1920x1080", "2560x1080"]]
        screenshots[0].pop("dom_assertions")
        report = subject.build_report(self.args(self.write_manifest(screenshots)))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("DOM assertions are missing", "\n".join(report["failures"]))
        self.assertEqual(report["visual_evidence_summary"]["dom_assertions"]["missing"], 1)

    def test_can_allow_missing_dom_assertions_for_planning(self):
        screenshots = [self.shot(page, viewport) for page in ["dashboard", "trace-viewer"] for viewport in ["390x844", "1366x768", "1920x1080", "2560x1080"]]
        screenshots[0].pop("dom_assertions")
        report = subject.build_report(self.args(self.write_manifest(screenshots), require_dom_assertions=False))
        self.assertEqual(report["status"], "pass")


if __name__ == "__main__":
    unittest.main()
