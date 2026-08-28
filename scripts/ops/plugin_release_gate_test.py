import importlib.util
import hashlib
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
        artifact = self.tmp / "sigma-extra-1.0.0.tar.gz"
        artifact.write_text("plugin bundle\n", encoding="utf-8")
        artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
        signature.write_text("sig\n", encoding="utf-8")
        signature_sha256 = hashlib.sha256(signature.read_bytes()).hexdigest()
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
                "artifact_sha256": artifact_sha256,
                "signature_sha256": signature_sha256,
            },
            "compatibility_tests": [
                {"providapt_version": "1.2.0", "status": "pass"},
                {"providapt_version": "1.3.0", "status": "pass"},
            ],
            "rollback": [
                "disable sigma-extra in providapt.toml",
                "restore the previous signed plugin bundle",
                "restart affected agents",
            ],
            "rollback_drill": {
                "status": "pass",
                "tested_at": "2026-08-12T00:00:00Z",
                "tested_by": "release-operator",
                "steps_verified": 3,
            },
        }), encoding="utf-8")
        report = plugin_gate.validate_manifest(plugin_gate.load_json(manifest), manifest, signature, False)
        self.assertEqual(report["status"], "pass")
        self.assertTrue(report["signature_present"])
        self.assertTrue(report["signature_hash_matches"])
        self.assertEqual(report["plugin"]["compatibility"]["providapt_max_version"], "1.3.0")
        self.assertTrue(report["plugin"]["artifact"]["hash_matches"])
        self.assertEqual(report["plugin"]["compatibility_pass_count"], 2)
        self.assertEqual(report["rollback_drill"]["status"], "pass")
        self.assertEqual(report["rollback"][0], "disable sigma-extra in providapt.toml")

    def test_unsigned_manifest_blocks_by_default(self):
        manifest = self.tmp / "plugin.json"
        manifest.write_text(json.dumps({
            "name": "sigma-extra",
            "version": "1.0.0",
            "type": "detection",
            "providapt_min_version": "1.2.0",
            "permissions": ["rules:read"],
            "distribution": {"channel": "signed-bundle", "artifact": "sigma-extra-1.0.0.tar.gz", "signature_algorithm": "ed25519", "artifact_sha256": "0" * 64, "signature_sha256": "0" * 64},
            "compatibility_tests": [{"providapt_version": "1.2.0", "status": "pass"}],
            "rollback": ["disable sigma-extra in providapt.toml"],
            "rollback_drill": {"status": "pass", "tested_at": "2026-08-12T00:00:00Z", "tested_by": "release-operator", "steps_verified": 1},
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
            "distribution": {"channel": "signed-bundle", "artifact": "unsafe-1.0.0.tar.gz", "signature_algorithm": "ed25519", "artifact_sha256": "0" * 64, "signature_sha256": "0" * 64},
            "compatibility_tests": [{"providapt_version": "1.2.0", "status": "pass"}],
            "rollback": ["disable unsafe in providapt.toml"],
            "rollback_drill": {"status": "pass", "tested_at": "2026-08-12T00:00:00Z", "tested_by": "release-operator", "steps_verified": 1},
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
        self.assertIn("compatibility_tests", failures)
        self.assertIn("rollback_drill evidence is required", failures)

    def test_blocks_incomplete_distribution_and_rollback_drill(self):
        manifest = self.tmp / "plugin.json"
        signature = self.tmp / "plugin.json.sig"
        manifest.write_text(json.dumps({
            "name": "incomplete-distribution",
            "version": "1.0.0",
            "type": "detection",
            "providapt_min_version": "1.2.0",
            "entrypoint": "pkg/plugin/incomplete",
            "permissions": ["events:read"],
            "distribution": {
                "channel": "signed-bundle",
                "artifact": "incomplete-1.0.0.tar.gz",
                "signature_algorithm": "sha1",
                "artifact_sha256": "not-a-sha",
                "signature_sha256": "not-a-sha",
            },
            "compatibility_tests": [{"providapt_version": "1.2.0", "status": "fail"}],
            "rollback": ["disable incomplete-distribution"],
            "rollback_drill": {
                "status": "fail",
                "tested_at": "",
                "tested_by": "",
                "steps_verified": 0,
            },
        }), encoding="utf-8")
        signature.write_text("sig\n", encoding="utf-8")
        report = plugin_gate.validate_manifest(plugin_gate.load_json(manifest), manifest, signature, False)
        failures = "\n".join(report["failures"])
        self.assertEqual(report["status"], "blocked")
        self.assertIn("distribution.signature_algorithm", failures)
        self.assertIn("distribution.artifact_sha256", failures)
        self.assertIn("distribution.signature_sha256", failures)
        self.assertIn("compatibility_tests[1].status", failures)
        self.assertIn("rollback_drill.status", failures)
        self.assertIn("rollback_drill.steps_verified", failures)

    def test_signature_hash_mismatch_blocks(self):
        manifest = self.tmp / "plugin.json"
        signature = self.tmp / "plugin.json.sig"
        artifact = self.tmp / "signed-1.0.0.tar.gz"
        artifact.write_text("plugin bundle\n", encoding="utf-8")
        signature.write_text("sig\n", encoding="utf-8")
        manifest.write_text(json.dumps({
            "name": "signed",
            "version": "1.0.0",
            "type": "detection",
            "providapt_min_version": "1.2.0",
            "entrypoint": "pkg/plugin/signed",
            "permissions": ["events:read"],
            "distribution": {
                "channel": "signed-bundle",
                "artifact": "signed-1.0.0.tar.gz",
                "signature_algorithm": "ed25519",
                "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "signature_sha256": "0" * 64,
            },
            "compatibility_tests": [{"providapt_version": "1.2.0", "status": "pass"}],
            "rollback": ["disable signed"],
            "rollback_drill": {"status": "pass", "tested_at": "2026-08-12T00:00:00Z", "tested_by": "release-operator", "steps_verified": 1},
        }), encoding="utf-8")
        report = plugin_gate.validate_manifest(plugin_gate.load_json(manifest), manifest, signature, False)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("distribution.signature_sha256 does not match signature file", report["failures"])


if __name__ == "__main__":
    unittest.main()
