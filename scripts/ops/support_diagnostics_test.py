import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("support-diagnostics.py")
SPEC = importlib.util.spec_from_file_location("support_diagnostics", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class SupportDiagnosticsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-support-diagnostics-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_text(self, name, text):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_builds_redacted_support_diagnostics_bundle(self):
        status = self.write_text("status.json", json.dumps({
            "version": "v1.2.4",
            "commit": "abc123",
            "agents": [{"id": "a1", "status": "healthy"}],
        }))
        config = self.write_text("providapt.toml", "api_key = 'redacted-test-value'\nrest = ':18080'\n")
        log = self.write_text("providapt.log", "started\nERROR failed to bind\n")
        report = subject.build_report(Namespace(
            status_json=str(status),
            config=str(config),
            log=str(log),
            server_url="http://vm-ubuntu-master:18080",
            port=["18080", "50051"],
            disk_path=[str(self.tmp)],
        ))
        self.assertEqual(report["schema"], "providapt.support_diagnostics.v1")
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["version"]["version"], "v1.2.4")
        self.assertEqual(report["config"]["redacted_keys"], ["api_key"])
        self.assertNotIn("redacted-test-value", json.dumps(report))
        self.assertEqual(report["logs"]["error_lines"], 1)
        self.assertEqual(report["connectivity"]["server_url"], "http://vm-ubuntu-master:18080")
        self.assertIn("18080", report["ports"])
        self.assertIn("Support Diagnostics", subject.render_markdown(report))


if __name__ == "__main__":
    unittest.main()
