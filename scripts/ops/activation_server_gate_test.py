import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("activation-server-gate.py")
SPEC = importlib.util.spec_from_file_location("activation_server_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class ActivationServerGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-activation-server-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, data):
        path = self.tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def write_audit(self, records):
        path = self.tmp / "activations.jsonl"
        path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
        return path

    def args(self, registry, audit, **overrides):
        values = {
            "customer_registry": str(registry),
            "activation_audit": str(audit),
            "allow_missing_audit": False,
            "server": "",
            "api_key": "",
            "activation_code": "",
            "machine_fingerprint": "FP-1",
            "negative_fingerprint": "",
            "timeout_seconds": 1.0,
        }
        values.update(overrides)
        return Namespace(**values)

    def complete_registry(self):
        return {
            "customers": [
                {
                    "activation_code": "ACME-2026",
                    "customer": "Acme Corp",
                    "edition": "enterprise",
                    "license_id": "lic-acme",
                    "max_agents": 250,
                    "valid_days": 730,
                    "allowed_fingerprints": ["FP-1"],
                }
            ]
        }

    def complete_audit(self):
        return [
            {"timestamp": "2026-08-01T00:00:00Z", "status": "issued", "license_id": "lic-acme", "activation_code_sha256": "a" * 64},
            {"timestamp": "2026-08-01T00:00:01Z", "status": "rejected", "message": "invalid activation code", "activation_code_sha256": "b" * 64},
        ]

    def test_passes_with_registry_and_audit_evidence(self):
        registry = self.write_json("customers.json", self.complete_registry())
        audit = self.write_audit(self.complete_audit())
        report = subject.build_report(self.args(registry, audit))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["registry"]["entitlements"], 1)
        self.assertEqual(report["audit"]["issued"], 1)
        self.assertEqual(report["audit"]["rejected"], 1)

    def test_blocks_missing_registry_fields(self):
        registry = self.write_json("customers.json", {"customers": [{"activation_code": "CODE"}]})
        audit = self.write_audit(self.complete_audit())
        report = subject.build_report(self.args(registry, audit))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("missing customer", "\n".join(report["failures"]))
        self.assertIn("max_agents must be positive", "\n".join(report["failures"]))

    def test_blocks_raw_activation_code_in_audit(self):
        registry = self.write_json("customers.json", self.complete_registry())
        records = self.complete_audit()
        records[0]["activation_code"] = "ACME-2026"
        audit = self.write_audit(records)
        report = subject.build_report(self.args(registry, audit))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("raw activation_code", "\n".join(report["failures"]))


if __name__ == "__main__":
    unittest.main()
