import json
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

import model_closed_loop as loop


class ModelClosedLoopTest(unittest.TestCase):
    def test_ready_when_metrics_registry_and_feedback_pass(self):
        root = Path.cwd() / ".tmp-tests" / "model-closed-loop" / uuid.uuid4().hex
        root.mkdir(parents=True, exist_ok=True)
        manifest = root / "manifest.json"
        metrics = root / "metrics.json"
        registry = root / "registry.json"
        feedback = root / "feedback.jsonl"
        manifest.write_text(json.dumps({"dataset_id": "ds1", "dataset_version": "1", "record_count": 1000}), encoding="utf-8")
        metrics.write_text(json.dumps({"accuracy": 0.97, "precision": 0.92, "recall": 0.91, "f1": 0.915}), encoding="utf-8")
        registry.write_text(json.dumps({"models": [{"model_name": "graph-detector", "model_version": "1.0.0"}]}), encoding="utf-8")
        feedback.write_text('{"alert_id":"a1","action":"annotate","classification":"true_positive"}\n', encoding="utf-8")
        args = SimpleNamespace(
            dataset_manifest=str(manifest),
            metrics=str(metrics),
            registry=str(registry),
            model_name="graph-detector",
            model_version="1.0.0",
            drift_report="",
            feedback=str(feedback),
            require_feedback=True,
            min_precision=70.0,
            min_recall=80.0,
            min_f1=70.0,
        )

        report = loop.build_report(args)

        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["feedback"]["records"], 1)
        self.assertEqual(report["feedback"]["reviewed"], 1)
        self.assertEqual(report["feedback"]["labels"]["true_positive"], 1)
        self.assertEqual(report["metrics"]["precision"], 92.0)

    def test_blocks_missing_registry_and_low_recall(self):
        root = Path.cwd() / ".tmp-tests" / "model-closed-loop" / uuid.uuid4().hex
        root.mkdir(parents=True, exist_ok=True)
        manifest = root / "manifest.json"
        metrics = root / "metrics.json"
        manifest.write_text(json.dumps({"dataset_id": "ds1", "record_count": 1000}), encoding="utf-8")
        metrics.write_text(json.dumps({"precision": 0.9, "recall": 0.4, "f1": 0.55}), encoding="utf-8")
        args = SimpleNamespace(
            dataset_manifest=str(manifest),
            metrics=str(metrics),
            registry=str(root / "missing.json"),
            model_name="graph-detector",
            model_version="1.0.0",
            drift_report="",
            feedback="",
            require_feedback=False,
            min_precision=70.0,
            min_recall=80.0,
            min_f1=70.0,
        )

        report = loop.build_report(args)

        self.assertEqual(report["status"], "review_required")
        failed = {item["name"] for item in report["gates"] if item["status"] == "fail"}
        self.assertIn("recall", failed)
        self.assertIn("registered_model", failed)

    def test_uses_dataset_manifest_feedback_when_file_not_supplied(self):
        root = Path.cwd() / ".tmp-tests" / "model-closed-loop" / uuid.uuid4().hex
        root.mkdir(parents=True, exist_ok=True)
        manifest = root / "manifest.json"
        metrics = root / "metrics.json"
        registry = root / "registry.json"
        manifest.write_text(json.dumps({
            "dataset_id": "ds1",
            "dataset_version": "1",
            "record_count": 1000,
            "alert_feedback": {
                "feedback_entry_count": 2,
                "feedback_by_classification": {"true_positive": 2},
                "feedback_alert_count": 2,
                "feedback_reviewed_count": 2,
            },
        }), encoding="utf-8")
        metrics.write_text(json.dumps({"precision": 0.92, "recall": 0.91, "f1": 0.915}), encoding="utf-8")
        registry.write_text(json.dumps({"models": [{"model_name": "graph-detector", "model_version": "1.0.0"}]}), encoding="utf-8")
        args = SimpleNamespace(
            dataset_manifest=str(manifest),
            metrics=str(metrics),
            registry=str(registry),
            model_name="graph-detector",
            model_version="1.0.0",
            drift_report="",
            feedback="",
            require_feedback=True,
            min_precision=70.0,
            min_recall=80.0,
            min_f1=70.0,
        )

        report = loop.build_report(args)

        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["feedback"]["source"], "dataset_manifest")
        self.assertEqual(report["feedback"]["records"], 2)
        self.assertEqual(report["feedback"]["reviewed"], 2)

    def test_require_feedback_blocks_unreviewed_feedback_only(self):
        root = Path.cwd() / ".tmp-tests" / "model-closed-loop" / uuid.uuid4().hex
        root.mkdir(parents=True, exist_ok=True)
        manifest = root / "manifest.json"
        metrics = root / "metrics.json"
        registry = root / "registry.json"
        feedback = root / "feedback.jsonl"
        manifest.write_text(json.dumps({"dataset_id": "ds1", "dataset_version": "1", "record_count": 1000}), encoding="utf-8")
        metrics.write_text(json.dumps({"precision": 0.92, "recall": 0.91, "f1": 0.915}), encoding="utf-8")
        registry.write_text(json.dumps({"models": [{"model_name": "graph-detector", "model_version": "1.0.0"}]}), encoding="utf-8")
        feedback.write_text('{"alert_id":"a1","action":"annotate","classification":"needs_review"}\n', encoding="utf-8")
        args = SimpleNamespace(
            dataset_manifest=str(manifest),
            metrics=str(metrics),
            registry=str(registry),
            model_name="graph-detector",
            model_version="1.0.0",
            drift_report="",
            feedback=str(feedback),
            require_feedback=True,
            min_precision=70.0,
            min_recall=80.0,
            min_f1=70.0,
        )

        report = loop.build_report(args)

        self.assertEqual(report["status"], "review_required")
        failed = {item["name"] for item in report["gates"] if item["status"] == "fail"}
        self.assertIn("reviewed_feedback_labels", failed)


if __name__ == "__main__":
    unittest.main()
