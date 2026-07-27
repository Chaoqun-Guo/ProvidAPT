import json
import shutil
import sys
import unittest
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import model_registry


class ModelRegistryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-model-registry-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_manifest(self, name, record_count, tactics=None, techniques=None):
        path = self.tmp / name
        data = {
            "dataset_id": name.replace(".json", ""),
            "dataset_version": "v1",
            "record_count": record_count,
            "split_summary": {
                "splits": {"train": int(record_count * 0.8), "test": record_count - int(record_count * 0.8)},
                "by_tactic": tactics or {"execution": record_count},
                "by_technique": techniques or {"T1059": record_count},
            },
        }
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_register_model_replaces_existing_version(self):
        manifest = self.write_manifest("manifest.json", 10)
        registry = self.tmp / "registry.json"
        args = Namespace(
            manifest=str(manifest),
            registry=str(registry),
            model_name="detector",
            model_version="1.0.0",
            metrics=None,
            commit="abc123",
            notes="release candidate",
        )
        model_registry.register_model(args)
        model_registry.register_model(args)
        data = json.loads(registry.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], model_registry.REGISTRY_SCHEMA)
        self.assertEqual(len(data["models"]), 1)
        self.assertEqual(data["models"][0]["dataset_record_count"], 10)
        self.assertEqual(data["models"][0]["commit"], "abc123")

    def test_drift_report_flags_large_distribution_change(self):
        baseline = self.write_manifest("baseline.json", 10, tactics={"execution": 10}, techniques={"T1059": 10})
        candidate = self.write_manifest(
            "candidate.json",
            20,
            tactics={"execution": 10, "exfiltration": 10},
            techniques={"T1059": 10, "T1041": 10},
        )
        report = model_registry.build_drift_report(
            json.loads(baseline.read_text(encoding="utf-8")),
            json.loads(candidate.read_text(encoding="utf-8")),
            20.0,
        )
        self.assertEqual(report["status"], "review_required")
        self.assertTrue(any("by_tactic:exfiltration" in item for item in report["warnings"]))
        self.assertIn("ProvidAPT Model Drift Report", model_registry.render_drift_markdown(report))


if __name__ == "__main__":
    unittest.main()
