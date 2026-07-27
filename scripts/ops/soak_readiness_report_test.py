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
            {"duration_hours": 24, "cpu_percent": 12, "memory_mb": 256, "disk_mb": 512, "events_dropped": 0},
            {"duration_hours": 25, "cpu_percent": 15, "memory_mb": 300, "disk_mb": 600, "events_dropped": 0},
        ]
        args = Namespace(min_hours=24, max_cpu_percent=25, max_memory_mb=512, max_disk_mb=4096, max_dropped_events=0)
        report = soak.build_report(rows, args)
        self.assertEqual(report["status"], "pass")
        self.assertIn("Soak Readiness", soak.render_markdown(report))

    def test_build_report_blocks_when_drops_exceed_budget(self):
        args = Namespace(min_hours=24, max_cpu_percent=25, max_memory_mb=512, max_disk_mb=4096, max_dropped_events=0)
        report = soak.build_report([{"duration_hours": 24, "events_dropped": 1}], args)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["checks"]["drops"]["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
