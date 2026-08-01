import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("support-bundle-gate.py")
SPEC = importlib.util.spec_from_file_location("support_bundle_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class SupportBundleGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-support-bundle-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def args(self, path, **overrides):
        values = {
            "support_summary": str(path),
            "require_archive": True,
            "require_redacted": True,
            "require_audit": True,
            "require_download": True,
            "check_files": False,
        }
        values.update(overrides)
        return Namespace(**values)

    def complete_summary(self):
        return {
            "last_bundle_path": "/var/lib/providapt/support-bundle/current",
            "last_archive_path": "/var/lib/providapt/support-bundle/current.zip",
            "last_status": "success",
            "redacted": True,
            "download_url": "/api/v1/control/support/download",
            "history": [{"action": "support_bundle_export", "status": "success"}],
        }

    def test_passes_complete_support_bundle_evidence(self):
        path = self.write_json("support.json", self.complete_summary())
        report = subject.build_report(self.args(path))
        self.assertEqual(report["status"], "pass")
        self.assertTrue(report["redacted"])

    def test_blocks_unredacted_archive(self):
        summary = self.complete_summary()
        summary["redacted"] = False
        path = self.write_json("support.json", summary)
        report = subject.build_report(self.args(path))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("redacted", "\n".join(report["failures"]))

    def test_blocks_missing_audit(self):
        summary = self.complete_summary()
        summary["history"] = []
        path = self.write_json("support.json", summary)
        report = subject.build_report(self.args(path))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("audit history", "\n".join(report["failures"]))


if __name__ == "__main__":
    unittest.main()
