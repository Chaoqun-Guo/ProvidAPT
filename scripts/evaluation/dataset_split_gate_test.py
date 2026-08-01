import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path

from scripts.evaluation import dataset_split_gate as subject


class DatasetSplitGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-dataset-split-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_manifest(self, value):
        path = self.tmp / "manifest.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def args(self, manifest, **overrides):
        values = {
            "manifest": str(manifest),
            "min_records": 3,
            "min_train": 1,
            "min_test": 1,
            "min_val": 0,
            "require_version": True,
            "require_train": True,
            "require_test": True,
            "require_val": False,
            "require_both_labels": True,
            "require_file_hashes": True,
        }
        values.update(overrides)
        return Namespace(**values)

    def complete_manifest(self):
        return {
            "dataset_id": "ds-1",
            "dataset_version": "2026.08.01",
            "record_count": 3,
            "train_count": 2,
            "test_count": 1,
            "label_summary": {"malicious": 1, "benign": 2},
            "files": {
                "labels": {"bytes": 10, "sha256": "a" * 64},
                "train": {"bytes": 10, "sha256": "b" * 64},
            },
        }

    def test_passes_complete_manifest(self):
        report = subject.build_report(self.args(self.write_manifest(self.complete_manifest())))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["dataset_version"], "2026.08.01")

    def test_blocks_missing_version_and_test_split(self):
        manifest = self.complete_manifest()
        manifest["dataset_version"] = ""
        manifest["test_count"] = 0
        report = subject.build_report(self.args(self.write_manifest(manifest)))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("dataset_version", "\n".join(report["failures"]))
        self.assertIn("test split", "\n".join(report["failures"]))

    def test_blocks_missing_label_balance(self):
        manifest = self.complete_manifest()
        manifest["label_summary"] = {"malicious": 3}
        report = subject.build_report(self.args(self.write_manifest(manifest)))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("both malicious and benign", "\n".join(report["failures"]))


if __name__ == "__main__":
    unittest.main()
