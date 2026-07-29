import importlib.util
import json
import shutil
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("github-actions-evidence.py")
SPEC = importlib.util.spec_from_file_location("github_actions_evidence", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class GitHubActionsEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-github-actions-evidence-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir(parents=True)

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_render_markdown_includes_failures(self):
        report = {
            "schema": subject.SCHEMA,
            "generated_at": "2026-07-28T00:00:00Z",
            "status": "blocked",
            "full_commit": "abc",
            "runs": [],
            "failures": ["not authenticated"],
        }
        text = subject.render_markdown(report)
        self.assertIn("GitHub Actions Evidence", text)
        self.assertIn("not authenticated", text)

    def test_report_json_round_trip_shape(self):
        path = self.tmp / "evidence.json"
        data = {
            "schema": subject.SCHEMA,
            "status": "pass",
            "full_commit": "abc",
            "runs": [{"workflowName": "CI", "status": "completed", "conclusion": "success", "url": "https://example.test"}],
        }
        path.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(json.loads(path.read_text())["schema"], subject.SCHEMA)


if __name__ == "__main__":
    unittest.main()
