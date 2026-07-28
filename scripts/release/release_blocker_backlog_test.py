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
        })
        self.assertEqual(backlog["task_count"], 2)
        self.assertEqual(backlog["tasks"][0]["severity"], "release_blocking")
        self.assertIn("Release Blocker Backlog", subject.render_markdown(backlog))


if __name__ == "__main__":
    unittest.main()
