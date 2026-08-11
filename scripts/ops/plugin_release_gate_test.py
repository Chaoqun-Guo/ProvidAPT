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
            "providapt_max_version": "1.3.0",
            "entrypoint": "pkg/plugin/sigma",
            "permissions": ["rules:read", "alerts:write"],
            "distribution": {
                "channel": "signed-bundle",
                "artifact": "sigma-extra-1.0.0.tar.gz",
                "signature_algorithm": "ed25519",
            },
            "rollback": [
                "disable sigma-extra in providapt.toml",
                "restore the previous signed plugin bundle",
                "restart affected agents",
            ],
        }), encoding="utf-8")
        signature.write_text("sig\n", encoding="utf-8")
        report = plugin_gate.validate_manifest(plugin_gate.load_json(manifest), manifest, signature, False)
        self.assertEqual(report["status"], "pass")
        self.assertTrue(report["signature_present"])
        self.assertEqual(report["plugin"]["compatibility"]["providapt_max_version"], "1.3.0")
        self.assertEqual(report["rollback"][0], "disable sigma-extra in providapt.toml")

    def test_unsigned_manifest_blocks_by_default(self):
        manifest = self.tmp / "plugin.json"
        manifest.write_text(json.dumps({
            "name": "sigma-extra",
            "version": "1.0.0",
            "type": "detection",
            "providapt_min_version": "1.2.0",
            "permissions": ["rules:read"],
            "distribution": {"channel": "signed-bundle", "artifact": "sigma-extra-1.0.0.tar.gz"},
            "rollback": ["disable sigma-extra in providapt.toml"],
        }), encoding="utf-8")
        report = plugin_gate.validate_manifest(plugin_gate.load_json(manifest), manifest, None, False)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("plugin signature evidence is required", report["failures"])

    def test_unsafe_plugin_permission_blocks(self):
        manifest = self.tmp / "plugin.json"
        signature = self.tmp / "plugin.json.sig"
        manifest.write_text(json.dumps({
            "name": "unsafe",
            "version": "1.0.0",
            "type": "enrichment",
            "providapt_min_version": "1.2.0",
            "permissions": ["*"],
            "distribution": {"channel": "signed-bundle", "artifact": "unsafe-1.0.0.tar.gz"},
            "rollback": ["disable unsafe in providapt.toml"],
        }), encoding="utf-8")
        signature.write_text("sig\n", encoding="utf-8")
        report = plugin_gate.validate_manifest(plugin_gate.load_json(manifest), manifest, signature, False)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("unsafe plugin permission", "\n".join(report["failures"]))

    def test_distribution_metadata_and_rollback_are_required(self):
        manifest = self.tmp / "plugin.json"
        signature = self.tmp / "plugin.json.sig"
        manifest.write_text(json.dumps({
            "name": "incomplete",
            "version": "1.0.0",
            "type": "detection",
            "providapt_min_version": "1.3.0",
            "providapt_max_version": "1.2.0",
            "entrypoint": "pkg/plugin/incomplete",
        }), encoding="utf-8")
        signature.write_text("sig\n", encoding="utf-8")
        report = plugin_gate.validate_manifest(plugin_gate.load_json(manifest), manifest, signature, False)
        failures = "\n".join(report["failures"])
        self.assertEqual(report["status"], "blocked")
        self.assertIn("permissions are required", failures)
        self.assertIn("distribution policy is required", failures)
        self.assertIn("rollback instructions are required", failures)
        self.assertIn("providapt_min_version must not be greater", failures)


if __name__ == "__main__":
    unittest.main()
