import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("open-source-development-backlog.py")
SPEC = importlib.util.spec_from_file_location("open_source_development_backlog", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class OpenSourceDevelopmentBacklogTest(unittest.TestCase):
    def test_build_report_groups_tasks(self):
        report = subject.build_report()
        self.assertEqual(report["schema"], subject.SCHEMA)
        self.assertGreaterEqual(report["task_count"], 8)
        self.assertIn("release", report["by_phase"])
        self.assertIn("blocked_external", report["by_status"])

    def test_local_only_filters_external_blockers(self):
        report = subject.build_report(local_only=True)
        self.assertTrue(report["tasks"])
        self.assertTrue(all(task["local"] for task in report["tasks"]))
        self.assertNotIn("release-owner-approval", {task["id"] for task in report["tasks"]})

    def test_phase_filter_and_markdown(self):
        report = subject.build_report(phase="frontend")
        self.assertEqual({task["phase"] for task in report["tasks"]}, {"frontend"})
        out = subject.render_markdown(report)
        self.assertIn("Open Source Development Backlog", out)
        self.assertIn("visual-browser-baselines", out)


if __name__ == "__main__":
    unittest.main()
