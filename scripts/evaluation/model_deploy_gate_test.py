import json
import shutil
import sys
import unittest
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import model_deploy_gate as gate


class ModelDeployGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-model-deploy-gate-test"
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

    def test_passes_registered_model_with_quality_and_schema(self):
        registry = self.write_json("registry.json", {"models": [{
            "model_name": "detector",
            "model_version": "1.0.0",
            "feature_schema": {"sha256": "abc", "vector_length": 15},
        }]})
        detection = self.write_json("quality.json", {"precision_percent": 80, "recall_percent": 90})
        schema = self.write_json("schema.json", {"status": "pass"})
        drift = self.write_json("drift.json", {"status": "stable"})
        report = gate.build_gate(Namespace(
            registry=str(registry),
            model_name="detector",
            model_version="1.0.0",
            detection_quality=str(detection),
            feature_schema_check=str(schema),
            drift_report=str(drift),
            min_precision=70,
            min_recall=80,
        ))
        self.assertEqual(report["status"], "pass")

    def test_blocks_missing_model_and_low_recall(self):
        registry = self.write_json("registry.json", {"models": []})
        detection = self.write_json("quality.json", {"precision_percent": 80, "recall_percent": 20})
        report = gate.build_gate(Namespace(
            registry=str(registry),
            model_name="detector",
            model_version="1.0.0",
            detection_quality=str(detection),
            feature_schema_check="",
            drift_report="",
            min_precision=70,
            min_recall=80,
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any("not registered" in item for item in report["failures"]))


if __name__ == "__main__":
    unittest.main()
