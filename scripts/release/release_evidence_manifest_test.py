import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("release-evidence-manifest.py")
SPEC = importlib.util.spec_from_file_location("release_evidence_manifest", SCRIPT)
manifest_mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(manifest_mod)


class ReleaseEvidenceManifestTest(unittest.TestCase):
    def test_indexes_markdown_and_json_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence_dir = root / "docs" / "project"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "vm-release-evidence.md").write_text(
                "# VM Evidence\n\nStatus: PASS\n",
                encoding="utf-8",
            )
            (evidence_dir / "visual-gate.json").write_text(
                json.dumps({"schema": "providapt.visual_regression_gate.v1", "status": "pass"}),
                encoding="utf-8",
            )
            report = manifest_mod.build_manifest(
                Namespace(
                    root=str(root),
                    evidence=[str(evidence_dir)],
                    exclude=[],
                    require_evidence=True,
                )
            )
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["evidence_count"], 2)
            self.assertEqual(report["status_counts"]["pass"], 2)
            self.assertIn("visual_regression_gate", {item["kind"] for item in report["evidence"]})
            rendered = manifest_mod.render_markdown(report)
            self.assertIn("Release Evidence Manifest", rendered)
            self.assertIn("vm-release-evidence.md", rendered)

    def test_blocks_on_failed_evidence_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "build" / "gate.json"
            evidence.parent.mkdir()
            evidence.write_text(json.dumps({"status": "blocked"}), encoding="utf-8")
            report = manifest_mod.build_manifest(
                Namespace(root=str(root), evidence=[str(evidence)], exclude=[], require_evidence=True)
            )
            self.assertEqual(report["status"], "blocked")
            self.assertTrue(report["blockers"])

    def test_blocks_when_required_evidence_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = manifest_mod.build_manifest(
                Namespace(root=str(root), evidence=[str(root / "missing")], exclude=[], require_evidence=True)
            )
            self.assertEqual(report["status"], "blocked")
            self.assertIn("no indexed evidence", report["blockers"][0])


if __name__ == "__main__":
    unittest.main()
