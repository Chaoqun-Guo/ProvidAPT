import importlib.util
import json
import shutil
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("open-source-development-backlog.py")
SPEC = importlib.util.spec_from_file_location("open_source_development_backlog", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class OpenSourceDevelopmentBacklogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-open-source-development-backlog-test"
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

    def test_evidence_paths_update_task_statuses(self):
        visual = self.write_json("visual.json", {"status": "pass"})
        model = self.write_json("model.json", {"status": "warn"})
        plugin = self.write_json("plugin.json", {"status": "blocked"})
        onboarding = self.write_json("onboarding.json", {"schema": "providapt.onboarding_bundle.v1", "outputs": {"config": "a", "checklist": "b"}})
        report = subject.build_report(local_only=True, evidence_paths={
            "visual_regression_gate": visual,
            "model_lifecycle_gate": model,
            "plugin_catalog_gate": plugin,
            "onboarding_manifest": onboarding,
        })
        tasks = {task["id"]: task for task in report["tasks"]}
        self.assertEqual(tasks["visual-browser-baselines"]["status"], "done")
        self.assertEqual(tasks["model-lifecycle-baseline"]["status"], "needs_review")
        self.assertEqual(tasks["plugin-distribution"]["status"], "needs_fix")
        self.assertEqual(tasks["onboarding-first-run-polish"]["status"], "done")
        self.assertEqual(report["by_evidence_status"]["pass"], 1)
        self.assertEqual(report["by_evidence_status"]["warn"], 1)
        rendered = subject.render_markdown(report)
        self.assertIn("visual_regression_gate:pass", rendered)


if __name__ == "__main__":
    unittest.main()
