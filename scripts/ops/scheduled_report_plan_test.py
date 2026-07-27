import importlib.util
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("scheduled-report-plan.py")
SPEC = importlib.util.spec_from_file_location("scheduled_report_plan", SCRIPT)
plan = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(plan)


class ScheduledReportPlanTest(unittest.TestCase):
    def test_valid_weekly_plan_passes(self):
        report = plan.validate_plan(Namespace(
            name="executive",
            cadence="1w",
            formats="markdown,json,bundle",
            recipients="secops@example.com",
            out_dir="/var/lib/providapt/reports",
            retention_days=90,
            max_report_mb=128,
        ))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["systemd"]["on_calendar"], "weekly")
        self.assertEqual(report["kubernetes"]["cron"], "0 2 * * 1")

    def test_invalid_format_blocks(self):
        report = plan.validate_plan(Namespace(
            name="bad",
            cadence="daily",
            formats="pdf",
            recipients="",
            out_dir="/tmp/reports",
            retention_days=0,
            max_report_mb=0,
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any("unsupported formats" in item for item in report["failures"]))
        self.assertTrue(any("cadence" in item for item in report["failures"]))


if __name__ == "__main__":
    unittest.main()
