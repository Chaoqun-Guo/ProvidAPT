import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detection_quality_report as quality


class DetectionQualityReportTest(unittest.TestCase):
    def test_report_merges_precision_recall_and_f1(self):
        coverage = {
            "schema": "providapt.attack_coverage.v1",
            "coverage_percent": 50,
            "by_tactic": {"execution": {"total": 2, "detected": 1, "missed": 1}},
            "by_technique": {"T1059": {"total": 2, "detected": 1, "missed": 1}},
        }
        alert_quality = {
            "schema": "providapt.alert_quality_report.v1",
            "actionable_precision_percent": 80,
            "review_coverage_percent": 90,
            "feedback": {
                "feedback_entries": 2,
                "feedback_matched_alerts": 1,
                "feedback_unmatched_alerts": 1,
                "feedback_by_classification": {"true_positive": 1, "false_positive": 1},
            },
        }
        report = quality.build_report(coverage, alert_quality)
        self.assertEqual(report["status"], "review_required")
        self.assertEqual(report["precision_percent"], 80)
        self.assertEqual(report["recall_percent"], 50)
        self.assertEqual(report["f1_percent"], 61.54)
        self.assertEqual(report["feedback"]["entries"], 2)
        self.assertEqual(report["feedback"]["unmatched_alerts"], 1)
        self.assertEqual(report["missed_techniques"][0]["key"], "T1059")
        self.assertIn("ProvidAPT Detection Quality Report", quality.render_markdown(report))

    def test_report_recommends_feedback_when_missing(self):
        report = quality.build_report(
            {"coverage_percent": 90, "by_technique": {}},
            {"actionable_precision_percent": 90, "review_coverage_percent": 90},
        )
        self.assertEqual(report["feedback"]["entries"], 0)
        self.assertIn("feedback ledger", "\n".join(report["recommendations"]))


if __name__ == "__main__":
    unittest.main()
