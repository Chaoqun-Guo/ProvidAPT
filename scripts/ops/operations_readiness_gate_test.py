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
        self.tmp = Path.cwd() / ".tmp-operations-readiness-gate-test"
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
            policy_approval_gate=str(paths["policy_approval"]),
            backup_readiness_gate=str(paths["backup"]),
            support_bundle_gate=str(paths["support"]),
            deployment_diagnostics_gate=str(paths["diagnostics"]),
            install_delivery_check=str(paths["install"]),
            observability_pack_check=str(paths["observability"]),
            security_hardening_gate=str(paths["security"]),
            visual_regression_gate=str(paths["visual"]),
            capture_enrichment_gate=str(paths["capture"]),
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
            "policy_approval": self.write_json("policy-approval.json", {"status": "pass", "approval_enabled": True, "tenant_scoped_keys": 1, "tenant_count": 1, "audit_matches": 1}),
            "backup": self.write_json("backup.json", {"status": "pass", "size_bytes": 4096, "history_count": 3, "restore_required": True, "cutover_required": True}),
            "support": self.write_json("support.json", {"status": "pass", "redacted": True, "history_count": 1, "export_events": 1}),
            "diagnostics": self.write_json("diagnostics.json", {"status": "pass", "api_auth_enabled": True, "tls_enabled": True, "kernel_attachment_mode": "lsm", "storage_encrypted": True, "applied_policy_version": 3}),
            "install": self.write_json("install.json", {"status": "pass"}),
            "observability": self.write_json("observability.json", {"status": "pass"}),
            "security": self.write_json("security.json", {"status": "pass"}),
            "visual": self.write_json("visual.json", {"status": "pass", "screenshot_count": 6, "comparison_count": 6}),
            "capture": self.write_json("capture.json", {"status": "pass", "summary": {"event_count": 100, "field_rates": {"cmdline_percent": 90, "exe_path_percent": 90, "pathname_percent": 100, "network_tuple_percent": 100}}}),
        }
        report = subject.build_report(self.args(**paths))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["sections"]["upgrade_rollout"]["status"], "pass")
        self.assertEqual(report["sections"]["policy_approval"]["status"], "pass")
        self.assertEqual(report["sections"]["backup_readiness"]["size_bytes"], 4096)
        self.assertTrue(report["sections"]["support_bundle"]["redacted"])
        self.assertEqual(report["sections"]["deployment_diagnostics"]["kernel_attachment_mode"], "lsm")
        self.assertEqual(report["sections"]["visual_regression"]["screenshots"], 6)
        self.assertEqual(report["sections"]["capture_enrichment"]["events"], 100)
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
            "policy_approval": self.write_json("policy-approval.json", {"status": "pass"}),
            "backup": self.write_json("backup.json", {"status": "pass"}),
            "support": self.write_json("support.json", {"status": "pass"}),
            "diagnostics": self.write_json("diagnostics.json", {"status": "pass"}),
            "install": self.write_json("install.json", {"status": "pass"}),
            "observability": self.write_json("observability.json", {"status": "pass"}),
            "security": self.write_json("security.json", {"status": "pass"}),
            "visual": self.write_json("visual.json", {"status": "pass"}),
            "capture": self.write_json("capture.json", {"status": "pass"}),
        }
        report = subject.build_report(self.args(**paths))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["soak_stability"]["status"], "blocked")

    def test_build_report_blocks_when_visual_or_capture_evidence_missing(self):
        missing = self.tmp / "missing.json"
        paths = {
            "production": self.write_json("production.json", {"status": "pass"}),
            "ml": self.write_json("ml.json", {"status": "pass"}),
            "fleet": self.write_json("fleet.json", {"status": "pass"}),
            "soak": self.write_json("soak.json", {"status": "pass"}),
            "upgrade": self.write_json("upgrade.json", {"status": "planned"}),
            "siem": self.write_json("siem.json", {"status": "pass"}),
            "rbac": self.write_json("rbac.json", {"status": "pass"}),
            "policy_approval": self.write_json("policy-approval.json", {"status": "pass"}),
            "backup": self.write_json("backup.json", {"status": "pass"}),
            "support": self.write_json("support.json", {"status": "pass"}),
            "diagnostics": self.write_json("diagnostics.json", {"status": "pass"}),
            "install": self.write_json("install.json", {"status": "pass"}),
            "observability": self.write_json("observability.json", {"status": "pass"}),
            "security": self.write_json("security.json", {"status": "pass"}),
            "visual": missing,
            "capture": missing,
        }
        report = subject.build_report(self.args(**paths))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["visual_regression"]["status"], "blocked")
        self.assertEqual(report["sections"]["capture_enrichment"]["status"], "blocked")

    def test_build_report_blocks_when_new_operations_gates_missing(self):
        missing = self.tmp / "missing.json"
        paths = {
            "production": self.write_json("production.json", {"status": "pass"}),
            "ml": self.write_json("ml.json", {"status": "pass"}),
            "fleet": self.write_json("fleet.json", {"status": "pass"}),
            "soak": self.write_json("soak.json", {"status": "pass"}),
            "upgrade": self.write_json("upgrade.json", {"status": "planned"}),
            "siem": self.write_json("siem.json", {"status": "pass"}),
            "rbac": self.write_json("rbac.json", {"status": "pass"}),
            "policy_approval": missing,
            "backup": missing,
            "support": missing,
            "diagnostics": missing,
            "install": self.write_json("install.json", {"status": "pass"}),
            "observability": self.write_json("observability.json", {"status": "pass"}),
            "security": self.write_json("security.json", {"status": "pass"}),
            "visual": self.write_json("visual.json", {"status": "pass"}),
            "capture": self.write_json("capture.json", {"status": "pass"}),
        }
        report = subject.build_report(self.args(**paths))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["policy_approval"]["status"], "blocked")
        self.assertEqual(report["sections"]["backup_readiness"]["status"], "blocked")
        self.assertEqual(report["sections"]["support_bundle"]["status"], "blocked")
        self.assertEqual(report["sections"]["deployment_diagnostics"]["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
