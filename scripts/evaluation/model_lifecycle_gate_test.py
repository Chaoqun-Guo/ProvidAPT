import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("model_lifecycle_gate.py")
SPEC = importlib.util.spec_from_file_location("model_lifecycle_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class ModelLifecycleGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-model-lifecycle-gate-test"
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

    def args(self, **overrides):
        values = {
            "closed_loop": "",
            "deploy_gate": "",
            "drift_report": "",
            "baseline_report": "",
            "approval": "",
            "require_approval": True,
            "require_baseline_report": False,
            "require_governance_bindings": False,
            "rollback_record": "",
            "min_feedback_records": 25,
            "min_reviewed_labels": 10,
            "required_feedback_label": ["true_positive", "false_positive"],
            "min_feedback_per_label": 1,
            "min_baseline_days": 7,
            "min_baseline_windows": 1,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_passes_mature_model_lifecycle(self):
        closed = self.write_json("closed.json", {
            "status": "ready",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "feature_schema_sha256": "a" * 64,
            "dataset": {"baseline_days": 14},
            "feedback": {"records": 40, "reviewed": 22, "labels": {"true_positive": 12, "false_positive": 7, "benign": 2, "duplicate": 1}},
            "drift": {"status": "stable"},
        })
        deploy = self.write_json("deploy.json", {"status": "pass", "model_name": "graph-detector", "model_version": "1.0.0", "feature_schema_sha256": "a" * 64})
        approval = self.write_json("approval.json", {
            "model_owner": {"decision": "approved", "approved_by": "Alice Model"},
            "security": {"decision": "approved", "approved_by": "Sam Security"},
            "soc_lead": {"decision": "approved", "approved_by": "Pat SOC"},
        })
        report = subject.build_report(self.args(closed_loop=str(closed), deploy_gate=str(deploy), approval=str(approval)))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["promotion_decision"], "approved_for_promotion")
        self.assertEqual(report["promotion_packet"]["evidence_count"], 3)
        self.assertEqual(len(report["promotion_packet"]["evidence_sha256"]["closed_loop"]), 64)
        self.assertEqual(report["promotion_packet"]["next_actions"], [])
        summary = report["promotion_packet"]["readiness_summary"]
        self.assertEqual(summary["decision"], "approved_for_promotion")
        self.assertIn("closed_loop", summary["evidence"]["present"])
        self.assertIn("drift_report", summary["evidence"]["missing"])
        self.assertEqual(summary["approvals"]["model_owner"]["owner"], "Alice Model")

    def test_blocks_missing_required_long_term_baseline(self):
        closed = self.write_json("closed.json", {
            "status": "ready",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "dataset": {"baseline_days": 14},
            "feedback": {"records": 40, "reviewed": 22, "labels": {"true_positive": 12, "false_positive": 7}},
            "drift": {"status": "stable"},
        })
        deploy = self.write_json("deploy.json", {"status": "pass", "model_name": "graph-detector", "model_version": "1.0.0"})
        report = subject.build_report(self.args(
            closed_loop=str(closed),
            deploy_gate=str(deploy),
            require_approval=False,
            require_baseline_report=True,
            min_baseline_windows=3,
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("long-term baseline report is missing", report["failures"])
        self.assertIn("baseline_report", report["promotion_packet"]["readiness_summary"]["evidence"]["missing"])

    def test_passes_long_term_baseline_report(self):
        closed = self.write_json("closed.json", {
            "status": "ready",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "dataset": {"baseline_days": 21},
            "feedback": {"records": 40, "reviewed": 22, "labels": {"true_positive": 12, "false_positive": 7}},
            "drift": {"status": "stable"},
        })
        deploy = self.write_json("deploy.json", {"status": "pass", "model_name": "graph-detector", "model_version": "1.0.0"})
        baseline = self.write_json("baseline.json", {
            "status": "stable",
            "observation_days": 21,
            "windows": [{"drift_percent": 1.2}, {"drift_percent": 2.5}, {"drift_percent": 1.7}],
        })
        report = subject.build_report(self.args(
            closed_loop=str(closed),
            deploy_gate=str(deploy),
            baseline_report=str(baseline),
            require_approval=False,
            require_baseline_report=True,
            min_baseline_windows=3,
        ))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["baseline_report"]["windows"], 3)
        self.assertIn("baseline_report", report["promotion_packet"]["readiness_summary"]["evidence"]["present"])

    def test_blocks_low_feedback_and_delegate_approval(self):
        closed = self.write_json("closed.json", {
            "status": "ready",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "dataset": {"baseline_days": 1},
            "feedback": {"records": 3, "reviewed": 1, "labels": {"true_positive": 1}},
            "drift": {"status": "review_required"},
        })
        deploy = self.write_json("deploy.json", {"status": "pass", "model_name": "graph-detector", "model_version": "1.0.0"})
        approval = self.write_json("approval.json", {
            "model_owner": {"decision": "approved", "approved_by": "Release delegate"},
        })
        report = subject.build_report(self.args(closed_loop=str(closed), deploy_gate=str(deploy), approval=str(approval)))
        self.assertEqual(report["status"], "blocked")
        text = "\n".join(report["failures"])
        self.assertIn("feedback records", text)
        self.assertIn("feedback label false_positive", text)
        self.assertIn("dataset drift", text)
        self.assertIn("named owner", text)
        actions = "\n".join(report["promotion_packet"]["next_actions"])
        self.assertIn("collect additional analyst", actions)
        self.assertIn("attach named", actions)

    def test_blocks_model_identity_mismatch(self):
        closed = self.write_json("closed.json", {
            "status": "ready",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "feature_schema_sha256": "a" * 64,
            "dataset": {"baseline_days": 14},
            "feedback": {"records": 40, "reviewed": 22, "labels": {"tp": 12, "fp": 10}},
            "drift": {"status": "stable"},
        })
        deploy = self.write_json("deploy.json", {
            "status": "pass",
            "model_name": "graph-detector",
            "model_version": "2.0.0",
            "feature_schema_sha256": "b" * 64,
        })
        approval = self.write_json("approval.json", {
            "model_owner": {"decision": "approved", "approved_by": "Alice Model"},
            "security": {"decision": "approved", "approved_by": "Sam Security"},
            "soc_lead": {"decision": "approved", "approved_by": "Pat SOC"},
        })
        report = subject.build_report(self.args(closed_loop=str(closed), deploy_gate=str(deploy), approval=str(approval)))
        self.assertEqual(report["status"], "blocked")
        text = "\n".join(report["failures"])
        self.assertIn("model version mismatch", text)
        self.assertIn("feature schema hash mismatch", text)

    def test_markdown_includes_promotion_packet_evidence(self):
        closed = self.write_json("closed.json", {
            "status": "ready",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "dataset": {"baseline_days": 14},
            "feedback": {"records": 40, "reviewed": 22, "labels": {"true_positive": 10, "false_positive": 8}},
            "drift": {"status": "stable"},
        })
        deploy = self.write_json("deploy.json", {
            "status": "pass",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
        })
        report = subject.build_report(self.args(closed_loop=str(closed), deploy_gate=str(deploy), require_approval=False))
        rendered = subject.render_markdown(report)
        self.assertIn("Promotion decision", rendered)
        self.assertIn("Readiness Summary", rendered)
        self.assertIn("Approvals", rendered)
        self.assertIn("Feedback Labels", rendered)
        self.assertIn("## Evidence", rendered)
        self.assertIn("closed_loop", rendered)

    def test_blocks_missing_required_feedback_label_diversity(self):
        closed = self.write_json("closed.json", {
            "status": "ready",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "dataset": {"baseline_days": 14},
            "feedback": {"records": 40, "reviewed": 22, "labels": {"true_positive": 22}},
            "drift": {"status": "stable"},
        })
        deploy = self.write_json("deploy.json", {
            "status": "pass",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
        })
        report = subject.build_report(self.args(
            closed_loop=str(closed),
            deploy_gate=str(deploy),
            require_approval=False,
            required_feedback_label=["true_positive", "false_positive", "benign", "duplicate"],
        ))
        self.assertEqual(report["status"], "blocked")
        text = "\n".join(report["failures"])
        self.assertIn("feedback label false_positive", text)
        self.assertIn("feedback label benign", text)
        self.assertIn("feedback label duplicate", text)

    def test_blocks_missing_model_governance_bindings_when_required(self):
        closed = self.write_json("closed.json", {
            "status": "ready",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "dataset": {"baseline_days": 14},
            "feedback": {"records": 40, "reviewed": 22, "labels": {"true_positive": 10, "false_positive": 8}},
            "drift": {"status": "stable"},
        })
        deploy = self.write_json("deploy.json", {
            "status": "pass",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
        })
        report = subject.build_report(self.args(
            closed_loop=str(closed),
            deploy_gate=str(deploy),
            require_approval=False,
            require_governance_bindings=True,
        ))
        self.assertEqual(report["status"], "blocked")
        failures = "\n".join(report["failures"])
        self.assertIn("training dataset hash is missing", failures)
        self.assertIn("feature schema hash is missing", failures)
        self.assertIn("model artifact hash is missing", failures)
        self.assertIn("rollback record is missing", failures)
        self.assertFalse(report["promotion_packet"]["governance_bindings"]["complete"])

    def test_passes_with_model_governance_bindings_and_rollback_record(self):
        dataset_sha = "1" * 64
        schema_sha = "2" * 64
        artifact_sha = "3" * 64
        closed = self.write_json("closed.json", {
            "status": "ready",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "feature_schema_sha256": schema_sha,
            "dataset": {
                "baseline_days": 14,
                "manifest": {"sha256": dataset_sha},
            },
            "feedback": {"records": 40, "reviewed": 22, "labels": {"true_positive": 10, "false_positive": 8}},
            "drift": {"status": "stable"},
        })
        deploy = self.write_json("deploy.json", {
            "status": "pass",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "feature_schema_sha256": schema_sha,
            "artifact": {"sha256": artifact_sha},
        })
        rollback = self.write_json("rollback.json", {
            "status": "ready",
            "target_model_version": "0.9.0",
            "artifact_sha256": "4" * 64,
            "validated_by": "Release Operator",
        })
        report = subject.build_report(self.args(
            closed_loop=str(closed),
            deploy_gate=str(deploy),
            require_approval=False,
            require_governance_bindings=True,
            rollback_record=str(rollback),
        ))
        self.assertEqual(report["status"], "pass")
        bindings = report["promotion_packet"]["governance_bindings"]
        self.assertTrue(bindings["complete"])
        self.assertEqual(bindings["training_dataset_sha256"], dataset_sha)
        self.assertEqual(bindings["feature_schema_sha256"], schema_sha)
        self.assertEqual(bindings["model_artifact_sha256"], artifact_sha)
        self.assertEqual(bindings["rollback"]["target_model_version"], "0.9.0")


if __name__ == "__main__":
    unittest.main()
