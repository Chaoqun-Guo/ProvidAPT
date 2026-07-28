import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("operations-readiness-gate.py")
SPEC = importlib.util.spec_from_file_location("operations_readiness_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class OperationsReadinessGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / "build" / "unit-tmp" / "operations-readiness-gate"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir(parents=True)

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def args(self, **paths):
        return Namespace(
            production_readiness_gate=str(paths["production"]),
            ml_readiness_gate=str(paths["ml"]),
            fleet_verification=str(paths["fleet"]),
            soak_readiness=str(paths["soak"]),
            upgrade_rollout=str(paths["upgrade"]),
            siem_verify=str(paths["siem"]),
            rbac_audit=str(paths["rbac"]),
        )

    def test_build_report_passes_when_all_evidence_passes(self):
        paths = {
            "production": self.write_json("production.json", {"status": "pass", "healthy_agents": 3}),
            "ml": self.write_json("ml.json", {"status": "pass", "sections": {
                "dataset_quality": {"records": 1000, "source_events": 10000, "truth_match_rate_percent": 100},
                "model_metrics": {"precision_percent": 90, "recall_percent": 91, "f1_percent": 90.5},
            }}),
            "fleet": self.write_json("fleet.json", {"status": "pass", "agent_count": 3, "healthy_count": 3}),
            "soak": self.write_json("soak.json", {"status": "pass", "sample_count": 24, "checks": {
                "duration": {"observed": 24}, "cpu": {"observed": 10}, "memory": {"observed": 100}, "disk": {"observed": 200}, "drops": {"observed": 0},
            }}),
            "upgrade": self.write_json("upgrade.json", {"status": "planned", "target_version": "v1.2.4", "fleet_size": 3, "eligible_agents": 3, "batches": [{"name": "canary"}]}),
            "siem": self.write_json("siem.json", {"status": "pass", "delivered": 3, "dead_letter": 0}),
            "rbac": self.write_json("rbac.json", {"status": "pass", "key_count": 2, "tenant_scoped_keys": 1}),
        }
        report = subject.build_report(self.args(**paths))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["sections"]["upgrade_rollout"]["status"], "pass")
        self.assertIn("Operations Readiness", subject.render_markdown(report))

    def test_build_report_blocks_when_soak_missing(self):
        missing = self.tmp / "missing.json"
        paths = {
            "production": self.write_json("production.json", {"status": "pass"}),
            "ml": self.write_json("ml.json", {"status": "pass"}),
            "fleet": self.write_json("fleet.json", {"status": "pass"}),
            "soak": missing,
            "upgrade": self.write_json("upgrade.json", {"status": "planned"}),
            "siem": self.write_json("siem.json", {"status": "pass"}),
            "rbac": self.write_json("rbac.json", {"status": "pass"}),
        }
        report = subject.build_report(self.args(**paths))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["soak_stability"]["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
