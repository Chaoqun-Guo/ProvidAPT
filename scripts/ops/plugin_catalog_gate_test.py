import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("plugin-catalog-gate.py")
SPEC = importlib.util.spec_from_file_location("plugin_catalog_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class PluginCatalogGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-plugin-catalog-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_gate(self, name, plugin_name="sigma-extra", version="1.0.0", status="pass"):
        path = self.tmp / name
        path.write_text(json.dumps({
            "status": status,
            "signature_present": True,
            "plugin": {
                "name": plugin_name,
                "version": version,
                "type": "detection",
                "permissions": ["rules:read", "alerts:write"],
                "distribution": {"channel": "signed-bundle", "artifact": f"{plugin_name}-{version}.tar.gz"},
                "compatibility": {"providapt_min_version": "1.2.0"},
            },
            "rollback": ["disable plugin", "restore previous bundle"],
            "failures": [] if status == "pass" else ["blocked"],
            "warnings": [],
        }), encoding="utf-8")
        return str(path)

    def args(self, **overrides):
        values = {
            "plugin_gate": [],
            "require_plugins": True,
            "require_signatures": True,
            "require_permissions": True,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_passes_signed_plugin_catalog(self):
        report = subject.build_report(self.args(plugin_gate=[
            self.write_gate("one.json", "sigma-extra", "1.0.0"),
            self.write_gate("two.json", "intel-extra", "1.1.0"),
        ]))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["plugin_count"], 2)
        self.assertIn("Plugin Catalog Gate", subject.render_markdown(report))

    def test_blocks_duplicate_plugin_identity(self):
        report = subject.build_report(self.args(plugin_gate=[
            self.write_gate("one.json", "sigma-extra", "1.0.0"),
            self.write_gate("two.json", "sigma-extra", "1.0.0"),
        ]))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("duplicate plugin identity", "\n".join(report["failures"]))

    def test_blocks_empty_required_catalog(self):
        report = subject.build_report(self.args(plugin_gate=[]))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("plugin catalog is empty", report["failures"])


if __name__ == "__main__":
    unittest.main()
