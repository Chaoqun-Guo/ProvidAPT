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
            "signature_sha256": "1" * 64,
            "signature_hash_matches": True,
            "plugin": {
                "name": plugin_name,
                "version": version,
                "type": "detection",
                "permissions": ["rules:read", "alerts:write"],
                "distribution": {"channel": "signed-bundle", "artifact": f"{plugin_name}-{version}.tar.gz", "artifact_sha256": "0" * 64},
                "compatibility": {"providapt_min_version": "1.2.0"},
                "compatibility_pass_count": 1,
                "artifact": {"present": True, "hash_matches": True},
            },
            "rollback": ["disable plugin", "restore previous bundle"],
            "rollback_drill": {"status": "pass", "tested_at": "2026-08-12T00:00:00Z", "tested_by": "release-operator", "steps_verified": 2},
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
        self.assertEqual(report["plugins"][0]["compatibility_pass_count"], 1)
        self.assertEqual(report["plugins"][0]["rollback_drill_status"], "pass")
        self.assertEqual(report["distribution_catalog"][0]["channel"], "signed-bundle")
        self.assertTrue(report["distribution_catalog"][0]["signed"])
        self.assertTrue(report["distribution_catalog"][0]["signature_hash_matches"])
        self.assertIn("alerts:write", report["distribution_catalog"][0]["permissions"])
        rendered = subject.render_markdown(report)
        self.assertIn("Plugin Catalog Gate", rendered)
        self.assertIn("Distribution Catalog", rendered)

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

    def test_blocks_missing_distribution_hardening_evidence(self):
        path = self.tmp / "weak.json"
        path.write_text(json.dumps({
            "status": "pass",
            "signature_present": True,
            "signature_sha256": "",
            "signature_hash_matches": False,
            "plugin": {
                "name": "weak",
                "version": "1.0.0",
                "type": "detection",
                "permissions": ["rules:read"],
                "distribution": {"channel": "signed-bundle", "artifact": "weak-1.0.0.tar.gz"},
                "compatibility": {"providapt_min_version": "1.2.0"},
                "compatibility_pass_count": 0,
            },
            "rollback": ["disable plugin", "restore previous bundle"],
            "rollback_drill": {"status": "fail", "steps_verified": 1},
            "failures": [],
            "warnings": [],
        }), encoding="utf-8")
        report = subject.build_report(self.args(plugin_gate=[str(path)]))
        failures = "\n".join(report["failures"])
        self.assertEqual(report["status"], "blocked")
        self.assertIn("artifact SHA-256 evidence is missing", failures)
        self.assertIn("signature SHA-256 evidence is missing", failures)
        self.assertIn("signature SHA-256 does not match", failures)
        self.assertIn("compatibility pass evidence is missing", failures)
        self.assertIn("rollback drill did not pass", failures)
        self.assertIn("rollback drill does not cover all steps", failures)


if __name__ == "__main__":
    unittest.main()
