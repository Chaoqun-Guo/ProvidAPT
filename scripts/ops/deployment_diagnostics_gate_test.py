import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("deployment-diagnostics-gate.py")
SPEC = importlib.util.spec_from_file_location("deployment_diagnostics_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class DeploymentDiagnosticsGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-deployment-diagnostics-gate-test"
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
            "status_json": str(path),
            "require_tls": True,
            "require_storage_encryption": True,
            "require_policy_sync": True,
            "require_kernel_attach": True,
            "require_support_bundle": True,
            "require_control_plane": True,
            "require_state_backend": True,
        }
        values.update(overrides)
        return Namespace(**values)

    def complete_status(self):
        return {
            "diagnostics": {
                "version": "v1.2.3",
                "open_source_control_plane": True,
                "tls_enabled": True,
                "kernel_attachment_mode": "lsm",
                "policy_enabled": True,
                "applied_policy_version": 3,
                "storage_encrypted": True,
                "control_plane_mode": "ha",
                "control_plane_state_backend": "postgres",
                "support_bundle_enabled": True,
                "output_dir": "/var/lib/providapt",
            }
        }

    def test_passes_complete_diagnostics(self):
        path = self.write_json("status.json", self.complete_status())
        report = subject.build_report(self.args(path))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["kernel_attachment_mode"], "lsm")

    def test_blocks_insecure_diagnostics(self):
        status = self.complete_status()
        status["diagnostics"]["storage_encrypted"] = False
        path = self.write_json("status.json", status)
        report = subject.build_report(self.args(path))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("storage encryption", "\n".join(report["failures"]))

    def test_accepts_flat_diagnostics_document(self):
        path = self.write_json("diag.json", self.complete_status()["diagnostics"])
        report = subject.build_report(self.args(path))
        self.assertEqual(report["status"], "pass")


if __name__ == "__main__":
    unittest.main()
