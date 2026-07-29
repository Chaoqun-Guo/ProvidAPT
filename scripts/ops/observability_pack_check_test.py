import importlib.util
import json
import shutil
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("observability-pack-check.py")
SPEC = importlib.util.spec_from_file_location("observability_pack_check", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(checker)


class ObservabilityPackCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-observability-pack-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_validates_prometheus_alerts_and_dashboard(self):
        prometheus = self.write("prometheus.yml", 'scrape_configs:\n- job_name: "providapt"\n  metrics_path: /metrics\n')
        alerts = self.write("alerts.yml", "ProvidaptNoEvents\nProvidaptBackpressure\nProvidaptCriticalAlert\nseverity: critical\n")
        dashboard = self.write("dashboard.json", json.dumps({"dashboard": {"title": "ProvidAPT Operations", "panels": [{"targets": [{"expr": "providapt_events_ingested_total"}]}, {"targets": [{"expr": "providapt_graph_nodes"}]}, {}, {}]}}))

        sections = {
            "prometheus": checker.check_prometheus(prometheus),
            "alerts": checker.check_alerts(alerts),
            "dashboard": checker.check_dashboard(dashboard),
        }

        self.assertEqual(checker.overall(sections), "pass")

    def test_blocks_missing_alert_rule(self):
        alerts = self.write("alerts.yml", "ProvidaptNoEvents\n")

        report = checker.check_alerts(alerts)

        self.assertEqual(report["status"], "blocked")

    def write(self, name, content):
        path = self.tmp / name
        path.write_text(content, encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
