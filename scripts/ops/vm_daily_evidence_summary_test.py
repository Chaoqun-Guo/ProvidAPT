import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("vm-daily-evidence-summary.py")
SPEC = importlib.util.spec_from_file_location("vm_daily_evidence_summary", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class VMDailyEvidenceSummaryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-vm-daily-evidence-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, payload):
        path = self.tmp / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return str(path)

    def test_builds_daily_summary_from_vm_evidence(self):
        report = subject.build_report(Namespace(
            capture_gate=self.write_json("capture.json", {"status": "pass", "summary": {"event_count": 42, "field_rates": {"pid_percent": 100.0}}}),
            capture_scenarios="",
            service_health=self.write_json("health.json", {"status": "pass", "hosts": [{"name": "vm-ubuntu-master", "status": "pass"}]}),
            trace_svg_stress=self.write_json("trace.json", {"status": "pass", "summary": {"requests": 12, "p95_ms": 80}}),
            visual_baseline=self.write_json("visual.json", {"status": "pass", "screenshots": [{"page": "dashboard"}]}),
            disk_log_budget=self.write_json("disk.json", {"status": "warn", "hosts": [{"name": "vm-centos-slave", "disk_percent": 79}]}),
            out_json=str(self.tmp / "summary.json"),
            out_md=str(self.tmp / "summary.md"),
        ))
        self.assertEqual(report["schema"], subject.SCHEMA)
        self.assertEqual(report["status"], "warn")
        self.assertEqual(report["sections"]["capture"]["status"], "pass")
        self.assertEqual(report["sections"]["disk_log_budget"]["status"], "warn")
        self.assertTrue(report["next_actions"])
        rendered = subject.render_markdown(report)
        self.assertIn("VM Continuous Evidence Daily Summary", rendered)
        self.assertIn("trace_svg_stress", rendered)

    def test_includes_capture_scenario_runner_when_provided(self):
        report = subject.build_report(Namespace(
            capture_gate=self.write_json("capture.json", {"status": "pass", "summary": {"event_count": 42}}),
            capture_scenarios=self.write_json("scenarios.json", {"status": "pass", "hosts": [{"host": "vm-a", "status": "pass"}]}),
            service_health=self.write_json("health.json", {"status": "pass"}),
            trace_svg_stress=self.write_json("trace.json", {"status": "pass"}),
            visual_baseline=self.write_json("visual.json", {"status": "pass"}),
            disk_log_budget=self.write_json("disk.json", {"status": "pass"}),
            out_json=str(self.tmp / "summary.json"),
            out_md=str(self.tmp / "summary.md"),
        ))

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["sections"]["capture_scenarios"]["status"], "pass")
        self.assertIn("capture_scenarios", subject.render_markdown(report))


if __name__ == "__main__":
    unittest.main()
