import importlib.util
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("soak-readiness-report.py")
SPEC = importlib.util.spec_from_file_location("soak_readiness_report", SCRIPT)
soak = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(soak)


class SoakReadinessReportTest(unittest.TestCase):
    def test_build_report_enforces_budgets(self):
        rows = [
            {"host": "vm-ubuntu-master", "duration_hours": 24, "cpu_percent": 12, "memory_mb": 256, "disk_mb": 512, "events_dropped": 0},
            {"host": "vm-centos-slave", "duration_hours": 25, "cpu_percent": 15, "memory_mb": 300, "disk_mb": 600, "events_dropped": 0},
        ]
        args = Namespace(min_samples=2, min_hosts=2, min_hours=24, max_cpu_percent=25, max_memory_mb=512, max_disk_mb=4096, max_dropped_events=0)
        report = soak.build_report(rows, args)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["checks"]["hosts"]["observed"], 2)
        self.assertIn("Soak Readiness", soak.render_markdown(report))

    def test_build_report_blocks_when_drops_exceed_budget(self):
        args = Namespace(min_samples=1, min_hosts=1, min_hours=24, max_cpu_percent=25, max_memory_mb=512, max_disk_mb=4096, max_dropped_events=0)
        report = soak.build_report([{"host": "vm-ubuntu-master", "duration_hours": 24, "events_dropped": 1}], args)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["checks"]["drops"]["status"], "blocked")

    def test_build_report_blocks_when_host_coverage_is_low(self):
        args = Namespace(min_samples=2, min_hosts=2, min_hours=24, max_cpu_percent=25, max_memory_mb=512, max_disk_mb=4096, max_dropped_events=0)
        report = soak.build_report([
            {"host": "vm-ubuntu-master", "duration_hours": 24, "events_dropped": 0},
            {"host": "vm-ubuntu-master", "duration_hours": 25, "events_dropped": 0},
        ], args)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["checks"]["hosts"]["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
