import importlib.util
import json
import shutil
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("capture-quality-trend.py")
SPEC = importlib.util.spec_from_file_location("capture_quality_trend", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class CaptureQualityTrendTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-capture-quality-trend-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_report(self, name, event_count, pid_rate, scenarios):
        path = self.tmp / name
        path.write_text(json.dumps({
            "status": "pass",
            "generated_at": "2026-09-05T00:00:00Z",
            "inputs": [f"/evidence/vm-ubuntu-master/{name}.ndjson"],
            "summary": {
                "event_count": event_count,
                "file_event_count": scenarios.get("file_activity", 0),
                "network_event_count": scenarios.get("network_activity", 0),
                "field_rates": {"pid_percent": pid_rate, "cmdline_percent": 25.0},
                "scenario_counts": scenarios,
            },
        }), encoding="utf-8")
        return path

    def test_builds_field_and_scenario_trends(self):
        first = self.write_report("first.json", 10, 90.0, {"shell_activity": 1, "file_activity": 3, "network_activity": 1, "process_chain": 8})
        second = self.write_report("second.json", 12, 100.0, {"shell_activity": 2, "file_activity": 4, "network_activity": 2, "process_chain": 10})
        report = subject.build_report([first, second])
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["total_events"], 22)
        self.assertEqual(report["field_trends"]["pid_percent"]["delta"], 10.0)
        self.assertEqual(report["scenario_totals"]["network_activity"], 3)
        self.assertIn("vm-ubuntu-master", report["hosts"])

    def test_warns_when_required_scenarios_are_missing(self):
        path = self.write_report("only.json", 3, 100.0, {"file_activity": 1})
        report = subject.build_report([path])
        self.assertEqual(report["status"], "warn")
        self.assertTrue(report["blockers"])


if __name__ == "__main__":
    unittest.main()
