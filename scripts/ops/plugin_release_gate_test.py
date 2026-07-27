import importlib.util
import json
import shutil
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("plugin-release-gate.py")
SPEC = importlib.util.spec_from_file_location("plugin_release_gate", SCRIPT)
plugin_gate = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(plugin_gate)


class PluginReleaseGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-plugin-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_valid_manifest_with_signature_passes(self):
        manifest = self.tmp / "plugin.json"
        signature = self.tmp / "plugin.json.sig"
        manifest.write_text(json.dumps({
            "name": "sigma-extra",
            "version": "1.0.0",
            "type": "detection",
            "providapt_min_version": "1.2.0",
            "entrypoint": "pkg/plugin/sigma",
        }), encoding="utf-8")
        signature.write_text("sig\n", encoding="utf-8")
        report = plugin_gate.validate_manifest(plugin_gate.load_json(manifest), manifest, signature, False)
        self.assertEqual(report["status"], "pass")
        self.assertTrue(report["signature_present"])

    def test_unsigned_manifest_blocks_by_default(self):
        manifest = self.tmp / "plugin.json"
        manifest.write_text(json.dumps({
            "name": "sigma-extra",
            "version": "1.0.0",
            "type": "detection",
            "providapt_min_version": "1.2.0",
        }), encoding="utf-8")
        report = plugin_gate.validate_manifest(plugin_gate.load_json(manifest), manifest, None, False)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("plugin signature evidence is required", report["failures"])


if __name__ == "__main__":
    unittest.main()
