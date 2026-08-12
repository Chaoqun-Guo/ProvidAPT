import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("open-source-milestone.py")
SPEC = importlib.util.spec_from_file_location("open_source_milestone", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class OpenSourceMilestoneTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-open-source-milestone-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def args(self, **overrides):
        missing = str(self.tmp / "missing.json")
        values = {
            "open_source_readiness_gate": missing,
            "open_source_readiness_backlog": missing,
            "open_source_development_backlog": missing,
            "release_gates": missing,
            "release_evidence_consistency_gate": missing,
            "model_lifecycle_gate": missing,
            "visual_regression_snapshots": missing,
            "allow_missing": False,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_allow_missing_turns_missing_inputs_into_warning(self):
        report = subject.build_report(self.args(allow_missing=True))
        self.assertEqual(report["status"], "warn")
        self.assertFalse(report["evidence"][0]["present"])
        self.assertIn("Open Source Milestone", subject.render_markdown(report))

    def test_task_backlog_without_status_is_usable_evidence(self):
        backlog = {"schema": "providapt.open_source_development_backlog.v1", "task_count": 8}
        self.assertEqual(subject.status_value(backlog, allow_missing=False), "pass")

    def test_complete_milestone_passes(self):
        readiness = self.write_json("readiness.json", {
            "schema": "providapt.open_source_readiness.v1",
            "status": "pass",
            "sections": {"docs": {"status": "pass"}},
        })
        readiness_backlog = self.write_json("readiness-backlog.json", {
            "schema": "providapt.release_blocker_backlog.v1",
            "source_status": "pass",
            "task_count": 0,
        })
        development_backlog = self.write_json("development-backlog.json", {
            "schema": "providapt.open_source_development_backlog.v1",
            "status": "pass",
            "task_count": 1,
        })
        release = self.write_json("release.json", {"status": "pass", "gates": []})
        release_evidence = self.write_json("release-evidence.json", {"status": "pass"})
        model = self.write_json("model.json", {
            "status": "pass",
            "promotion_packet": {
                "readiness_summary": {
                    "decision": "approved_for_promotion",
                    "model": {"name": "graph-detector", "version": "1.0.0"},
                    "drift_status": "stable",
                    "baseline_days": 14,
                    "feedback": {
                        "records": 40,
                        "reviewed": 22,
                        "labels": {"false_positive": 8, "true_positive": 10},
                    },
                    "blocker_count": 0,
                    "warning_count": 0,
                    "evidence": {"present": ["closed_loop", "deploy_gate"], "missing": ["approval"]},
                }
            },
        })
        visual = self.write_json("visual.json", {"status": "pass"})
        report = subject.build_report(self.args(
            open_source_readiness_gate=readiness,
            open_source_readiness_backlog=readiness_backlog,
            open_source_development_backlog=development_backlog,
            release_gates=release,
            release_evidence_consistency_gate=release_evidence,
            model_lifecycle_gate=model,
            visual_regression_snapshots=visual,
        ))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["evidence"][0]["section_count"], 1)
        self.assertEqual(report["evidence"][1]["task_count"], 0)
        model_row = next(item for item in report["evidence"] if item["name"] == "model_lifecycle")
        self.assertEqual(model_row["model_lifecycle"]["promotion_decision"], "approved_for_promotion")
        self.assertEqual(model_row["model_lifecycle"]["feedback_labels"]["true_positive"], 10)
        rendered = subject.render_markdown(report)
        self.assertIn("model=graph-detector:1.0.0", rendered)
        self.assertIn("decision=approved_for_promotion", rendered)
        self.assertIn("missing_evidence=approval", rendered)


if __name__ == "__main__":
    unittest.main()
