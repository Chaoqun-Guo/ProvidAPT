import shutil
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_gate_status as gates


class ReleaseGateStatusTest(unittest.TestCase):
    def setUp(self):
        self.tmp_root = Path.cwd() / ".tmp-release-gate-tests"
        if self.tmp_root.exists():
            shutil.rmtree(self.tmp_root)
        self.tmp_root.mkdir()

    def tearDown(self):
        if self.tmp_root.exists():
            shutil.rmtree(self.tmp_root)

    def test_render_markdown_escapes_table_pipes(self):
        report = {
            "generated_at": "2026-07-27T00:00:00Z",
            "full_commit": "abcdef",
            "version": "v1",
            "gates": [
                {
                    "name": "scan",
                    "status": "blocked",
                    "message": "a | b",
                    "next_action": "fix | rerun",
                    "evidence": "x",
                }
            ],
        }
        text = gates.render_markdown(report)
        self.assertIn("a \\| b", text)
        self.assertIn("fix \\| rerun", text)

    def test_artifact_gate_requires_checksums_signature_and_sboms(self):
        dist = self.tmp_root / "dist"
        dist.mkdir()
        blocked = gates.artifact_gate(dist)
        self.assertEqual(blocked.status, "blocked")
        (dist / "checksums.txt").write_text("abc  artifact\n", encoding="utf-8")
        (dist / "checksums.txt.sig").write_text("sig\n", encoding="utf-8")
        (dist / "providapt.spdx.json").write_text("{}\n", encoding="utf-8")
        (dist / "providapt.cdx.json").write_text("{}\n", encoding="utf-8")
        passed = gates.artifact_gate(dist)
        self.assertEqual(passed.status, "pass")

    def test_scan_evidence_accepts_any_nonempty_file(self):
        path = self.tmp_root / "scan.json"
        self.assertEqual(gates.scan_evidence_gate("scan", [path], "run").status, "blocked")
        path.write_text("{}\n", encoding="utf-8")
        self.assertEqual(gates.scan_evidence_gate("scan", [path], "run").status, "pass")


if __name__ == "__main__":
    unittest.main()
