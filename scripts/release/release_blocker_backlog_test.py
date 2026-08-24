import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("release-blocker-backlog.py")
SPEC = importlib.util.spec_from_file_location("release_blocker_backlog", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class ReleaseBlockerBacklogTest(unittest.TestCase):
    def test_build_backlog_extracts_failures_and_warnings(self):
        backlog = subject.build_backlog({
            "status": "blocked",
            "sections": {
                "dist_artifacts": {"status": "blocked", "failures": ["missing checksums"]},
                "legal_documents": {"status": "warn", "warnings": ["placeholder remains"]},
                "ml_readiness": {"status": "pass"},
            },
        }, "operator-release")
        self.assertEqual(backlog["task_count"], 2)
        self.assertEqual(backlog["source_label"], "operator-release")
        self.assertEqual(backlog["tasks"][0]["severity"], "release_blocking")
        self.assertEqual(backlog["checklist_summary"]["section_count"], 3)
        self.assertEqual(backlog["checklist_summary"]["release_blocking_count"], 1)
        self.assertIn("ml_readiness", backlog["checklist_summary"]["passing_sections"])
        rendered = subject.render_markdown(backlog)
        self.assertIn("Release Blocker Backlog", rendered)
        self.assertIn("## Checklist", rendered)
        self.assertIn("| ml_readiness | pass | false | 0 |", rendered)

    def test_open_source_readiness_sections_have_specific_actions(self):
        backlog = subject.build_backlog({
            "status": "warn",
            "sections": {
                "model_lifecycle": {"status": "warn", "warnings": ["model lifecycle promotion packet was not supplied"]},
                "visual_baselines": {"status": "blocked", "failures": ["visual baseline matrix is incomplete"]},
            },
        }, "open-source-readiness")
        self.assertEqual(backlog["task_count"], 2)
        actions = "\n".join(task["recommended_action"] for task in backlog["tasks"])
        self.assertIn("model-lifecycle-gate", actions)
        self.assertIn("browser baseline matrix", actions)
        self.assertEqual(backlog["checklist_summary"]["warning_sections"], ["model_lifecycle"])
        self.assertEqual(backlog["checklist_summary"]["blocked_sections"], ["visual_baselines"])
        self.assertIn("open-source-readiness", subject.render_markdown(backlog))


if __name__ == "__main__":
    unittest.main()
