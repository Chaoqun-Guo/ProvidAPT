import json
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import alert_quality_report as quality


class AlertQualityReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-alert-quality-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_report_computes_precision_and_recommendations(self):
        path = self.tmp / "alerts.ndjson"
        rows = [
            {"id": "a1", "pattern": "curl-egress", "severity": "high", "details": {"classification": "true_positive"}},
            {"id": "a2", "pattern": "backup-shell", "severity": "medium", "details": {"classification": "false_positive"}},
            {"id": "a3", "pattern": "backup-shell", "severity": "medium", "details": {"classification": "benign"}},
            {"id": "a4", "pattern": "backup-shell", "severity": "medium"},
        ]
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        report = quality.build_report(quality.load_alerts([path]), [path])
        self.assertEqual(report["total_alerts"], 4)
        self.assertEqual(report["reviewed_alerts"], 3)
        self.assertEqual(report["unreviewed_alerts"], 1)
        self.assertEqual(report["actionable_precision_percent"], 33.33)
        self.assertEqual(report["recommendations"][0]["pattern"], "backup-shell")

    def test_deduplicates_by_alert_id(self):
        path = self.tmp / "alerts.ndjson"
        path.write_text(
            json.dumps({"id": "a1", "pattern": "p", "details": {"classification": "false_positive"}})
            + "\n"
            + json.dumps({"id": "a1", "pattern": "p", "details": {"classification": "true_positive"}})
            + "\n",
            encoding="utf-8",
        )
        report = quality.build_report(quality.load_alerts([path]), [path])
        self.assertEqual(report["total_alerts"], 1)
        self.assertEqual(report["true_positive"], 1)


if __name__ == "__main__":
    unittest.main()
