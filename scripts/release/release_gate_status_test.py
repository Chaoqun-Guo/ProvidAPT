import shutil
import unittest
from pathlib import Path
import sys
import json

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
        (dist / "release-readiness.md").write_text("Commit `abc123`\nVersion `v1`\n", encoding="utf-8")
        passed = gates.artifact_gate(dist)
        self.assertEqual(passed.status, "pass")
        stale = gates.artifact_gate(dist, "def456", "v1")
        self.assertEqual(stale.status, "blocked")

    def test_scan_evidence_accepts_any_nonempty_file(self):
        path = self.tmp_root / "scan.json"
        self.assertEqual(gates.scan_evidence_gate("scan", [path], "run").status, "blocked")
        path.write_text("{}\n", encoding="utf-8")
        self.assertEqual(gates.scan_evidence_gate("scan", [path], "run").status, "pass")

    def test_waiver_gate_accepts_structured_waiver(self):
        waiver = self.tmp_root / "waivers.json"
        waiver.write_text(
            '{"waivers":[{"gate":"grype_evidence","status":"approved_with_risk","reason":"local scanner unavailable","approved_by":"security"}]}\n',
            encoding="utf-8",
        )
        blocked = gates.Gate("grype_evidence", "blocked", "missing")
        result = gates.waiver_gate("grype_evidence", [waiver], ["grype_evidence", "grype"], blocked)
        self.assertEqual(result.status, "waived")

    def test_waiver_gate_requires_reason_and_approval(self):
        waiver = self.tmp_root / "waivers.json"
        waiver.write_text('{"waivers":[{"gate":"grype_evidence","status":"approved_with_risk"}]}\n', encoding="utf-8")
        blocked = gates.Gate("grype_evidence", "blocked", "missing")
        result = gates.waiver_gate("grype_evidence", [waiver], ["grype_evidence", "grype"], blocked)
        self.assertEqual(result.status, "blocked")

    def test_ci_gate_accepts_external_commit_evidence(self):
        evidence = self.tmp_root / "ci.md"
        commit = "abcdef123456"
        evidence.write_text(f"GitHub Actions approved for CI commit {commit}\n", encoding="utf-8")
        result = gates.ci_gate(self.tmp_root, commit, [evidence])
        self.assertEqual(result.status, "pass")

    def test_ci_gate_accepts_structured_github_actions_evidence(self):
        evidence = self.tmp_root / "github-actions.json"
        commit = "abcdef123456"
        evidence.write_text(
            json.dumps({
                "schema": "providapt.github_actions_evidence.v1",
                "full_commit": commit,
                "runs": [{"workflowName": "CI", "status": "completed", "conclusion": "success", "url": "https://example.test/run"}],
            }),
            encoding="utf-8",
        )
        result = gates.ci_gate(self.tmp_root, commit, [evidence])
        self.assertEqual(result.status, "pass")

    def test_ci_gate_blocks_structured_evidence_for_wrong_commit(self):
        evidence = self.tmp_root / "github-actions.json"
        evidence.write_text(
            json.dumps({
                "schema": "providapt.github_actions_evidence.v1",
                "full_commit": "abc",
                "runs": [{"workflowName": "CI", "status": "completed", "conclusion": "success"}],
            }),
            encoding="utf-8",
        )
        result = gates.ci_gate(self.tmp_root, "def", [evidence])
        self.assertEqual(result.status, "blocked")

    def test_collect_can_skip_ci_gate(self):
        dist = self.tmp_root / "dist"
        security = self.tmp_root / "security"
        dist.mkdir()
        security.mkdir()
        report = gates.collect(self.tmp_root, dist, security, skip_ci=True)
        github = next(gate for gate in report["gates"] if gate["name"] == "github_actions")
        self.assertEqual(github["status"], "skipped")

    def test_approval_gate_blocks_pending_markers(self):
        approval = self.tmp_root / "approval.md"
        approval.write_text("Product requires approval from external owner required\n", encoding="utf-8")
        self.assertEqual(gates.approval_gate(approval).status, "blocked")


if __name__ == "__main__":
    unittest.main()
