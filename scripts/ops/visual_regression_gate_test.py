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
        }

    def args(self, manifest, **overrides):
        values = {
            "manifest": str(manifest),
            "required_page": ["dashboard", "trace-viewer"],
            "required_viewport": ["1366x768", "1920x1080", "2560x1080"],
            "require_captured": True,
            "require_files": True,
            "require_hash": True,
            "block_changed": True,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_passes_complete_captured_manifest(self):
        screenshots = [self.shot(page, viewport) for page in ["dashboard", "trace-viewer"] for viewport in ["1366x768", "1920x1080", "2560x1080"]]
        report = subject.build_report(self.args(self.write_manifest(screenshots)))
        self.assertEqual(report["status"], "pass")

    def test_blocks_missing_viewport(self):
        screenshots = [self.shot("dashboard", "1366x768")]
        report = subject.build_report(self.args(self.write_manifest(screenshots)))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("missing screenshot: trace-viewer 2560x1080", "\n".join(report["failures"]))

    def test_blocks_changed_baseline_by_default(self):
        screenshots = [self.shot(page, viewport) for page in ["dashboard", "trace-viewer"] for viewport in ["1366x768", "1920x1080", "2560x1080"]]
        manifest = self.write_manifest(screenshots, [{"page": "dashboard", "viewport": "1366x768", "status": "changed"}])
        report = subject.build_report(self.args(manifest))
        self.assertEqual(report["status"], "blocked")

    def test_can_warn_on_changed_baseline(self):
        screenshots = [self.shot(page, viewport) for page in ["dashboard", "trace-viewer"] for viewport in ["1366x768", "1920x1080", "2560x1080"]]
        manifest = self.write_manifest(screenshots, [{"page": "dashboard", "viewport": "1366x768", "status": "changed"}])
        report = subject.build_report(self.args(manifest, block_changed=False))
        self.assertEqual(report["status"], "warn")


if __name__ == "__main__":
    unittest.main()
