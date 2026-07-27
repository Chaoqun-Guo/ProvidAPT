import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import attack_coverage_plan as plan


class AttackCoveragePlanTest(unittest.TestCase):
    def test_build_plan_prioritizes_zero_recall(self):
        report = {
            "schema": "providapt.detection_quality_report.v1",
            "missed_techniques": [{"key": "T1059.004", "total": 2, "detected": 0, "missed": 2, "recall_percent": 0}],
        }
        result = plan.build_plan(report)
        self.assertEqual(result["status"], "planned")
        self.assertEqual(result["tasks"][0]["priority"], "P1")
        self.assertIn("Unix Shell", result["tasks"][0]["technique_name"])
        self.assertIn("ATT&CK Coverage Plan", plan.render_markdown(result))


if __name__ == "__main__":
    unittest.main()
