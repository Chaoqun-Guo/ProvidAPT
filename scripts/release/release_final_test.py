import importlib.util
import unittest
from argparse import Namespace


SCRIPT = __import__("pathlib").Path(__file__).with_name("release-final.py")
SPEC = importlib.util.spec_from_file_location("release_final", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class ReleaseFinalTest(unittest.TestCase):
    def test_builds_ordered_final_release_plan(self):
        report = subject.build_plan(Namespace(
            version="v1.2.4",
            release_tag="v1.2.4",
            evidence_doc="docs/project/release-evidence-v1.2.4.md",
            dist_dir="dist",
            security_dir="build/security",
            commit="abc123",
            dry_run=True,
            skip_push=True,
        ))
        self.assertEqual(report["schema"], "providapt.release_final_plan.v1")
        self.assertEqual(report["status"], "planned")
        ids = [step["id"] for step in report["steps"]]
        self.assertEqual(ids[0], "github_actions_evidence")
        self.assertLess(ids.index("release_evidence_manifest"), ids.index("tag_final_release"))
        self.assertLess(ids.index("operator_release_gate"), ids.index("tag_final_release"))
        self.assertIn("make github-actions-evidence", report["steps"][0]["command"])
        self.assertIn("git tag -a v1.2.4", report["steps"][-2]["command"])
        self.assertIn("Release Final Plan", subject.render_markdown(report))


if __name__ == "__main__":
    unittest.main()
