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
        self.assertEqual(report["visual_evidence_summary"]["dom_assertions"]["total"], 8)
        self.assertIn("Evidence Summary", subject.render_markdown(report))

    def test_blocks_missing_viewport(self):
        screenshots = [self.shot("dashboard", "1366x768")]
        report = subject.build_report(self.args(self.write_manifest(screenshots)))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("missing screenshot: trace-viewer 2560x1080", "\n".join(report["failures"]))
        self.assertIn("missing screenshot: dashboard 390x844", "\n".join(report["failures"]))
        self.assertGreater(report["visual_evidence_summary"]["required_matrix"]["missing_count"], 0)

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
        screenshots[0]["dom_assertions"] = {"status": "fail"}
        report = subject.build_report(self.args(self.write_manifest(screenshots)))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("DOM assertions failed", "\n".join(report["failures"]))
        self.assertEqual(report["visual_evidence_summary"]["dom_assertions"]["failed"], 1)

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
