import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("enterprise-readiness-report.py")
SPEC = importlib.util.spec_from_file_location("enterprise_readiness_report", SCRIPT)
enterprise = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(enterprise)


class EnterpriseReadinessReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-enterprise-readiness-test"
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

    def test_build_report_blocks_on_release_gate(self):
        release = self.write_json("release.json", {"gates": [{"name": "ci", "status": "blocked"}]})
        secrets = self.write_json("secrets.json", {"outputs": {"systemd_dropin": "a", "docker_compose": "b", "kubernetes_secret": "c"}, "variable_count": 3})
        postgres = self.write_json("postgres.json", {"backup": {"status": "pass"}, "restore": {"status": "pass"}})
        detection = self.write_json("detection.json", {"status": "pass", "precision_percent": 80, "recall_percent": 90})
        rbac = self.write_json("rbac.json", {"status": "pass", "key_count": 2, "tenant_scoped_keys": 1})
        report_plan = self.write_json("report-plan.json", {"status": "pass", "cadence": "1w", "formats": ["markdown", "json"]})
        siem = self.write_json("siem.json", {"status": "pass", "endpoint": "file:///tmp/siem.ndjson", "delivered": 3, "dead_letter": 0})
        upgrade = self.write_json("upgrade.json", {"status": "planned", "target_version": "v1.2.4", "batches": [{"name": "canary"}]})
        report = enterprise.build_report(Namespace(
            release_gates=str(release),
            secret_manifest=str(secrets),
            postgres_drill=str(postgres),
            detection_quality=str(detection),
            rbac_audit=str(rbac),
            report_plan=str(report_plan),
            siem_verify=str(siem),
            upgrade_rollout=str(upgrade),
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["secret_backends"]["status"], "pass")
        self.assertEqual(report["sections"]["rbac_audit"]["status"], "pass")
        self.assertEqual(report["sections"]["scheduled_reports"]["status"], "pass")
        self.assertEqual(report["sections"]["siem_soar_delivery"]["status"], "pass")
        self.assertEqual(report["sections"]["upgrade_rollout"]["status"], "pass")
        self.assertIn("Enterprise Readiness", enterprise.render_markdown(report))


if __name__ == "__main__":
    unittest.main()
