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
        report = enterprise.build_report(Namespace(release_gates=str(release), secret_manifest=str(secrets), postgres_drill=str(postgres), detection_quality=str(detection)))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["secret_backends"]["status"], "pass")
        self.assertIn("Enterprise Readiness", enterprise.render_markdown(report))


if __name__ == "__main__":
    unittest.main()
