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
            "approval": "",
            "require_approval": True,
            "min_feedback_records": 25,
            "min_reviewed_labels": 10,
            "min_baseline_days": 7,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_passes_mature_model_lifecycle(self):
        closed = self.write_json("closed.json", {
            "status": "ready",
            "model_name": "graph-detector",
            "model_version": "1.0.0",
            "dataset": {"baseline_days": 14},
            "feedback": {"records": 40, "reviewed": 22},
            "drift": {"status": "stable"},
        })
        deploy = self.write_json("deploy.json", {"status": "pass"})
        approval = self.write_json("approval.json", {
            "model_owner": {"decision": "approved", "approved_by": "Alice Model"},
            "security": {"decision": "approved", "approved_by": "Sam Security"},
            "soc_lead": {"decision": "approved", "approved_by": "Pat SOC"},
        })
        report = subject.build_report(self.args(closed_loop=str(closed), deploy_gate=str(deploy), approval=str(approval)))
        self.assertEqual(report["status"], "pass")

    def test_blocks_low_feedback_and_delegate_approval(self):
        closed = self.write_json("closed.json", {
            "status": "ready",
            "dataset": {"baseline_days": 1},
            "feedback": {"records": 3, "reviewed": 1},
            "drift": {"status": "review_required"},
        })
        deploy = self.write_json("deploy.json", {"status": "pass"})
        approval = self.write_json("approval.json", {
            "model_owner": {"decision": "approved", "approved_by": "Release delegate"},
        })
        report = subject.build_report(self.args(closed_loop=str(closed), deploy_gate=str(deploy), approval=str(approval)))
        self.assertEqual(report["status"], "blocked")
        text = "\n".join(report["failures"])
        self.assertIn("feedback records", text)
        self.assertIn("dataset drift", text)
        self.assertIn("named owner", text)


if __name__ == "__main__":
    unittest.main()
