import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("release-evidence-consistency-gate.py")
SPEC = importlib.util.spec_from_file_location("release_evidence_consistency_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class ReleaseEvidenceConsistencyGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-release-evidence-consistency-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()
        self.dist = self.tmp / "dist"
        self.dist.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, path, value):
        target = self.tmp / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value), encoding="utf-8")
        return target

    def args(self, **overrides):
        version = "v1.2.3"
        full_commit = "a" * 40
        short_commit = "a" * 7
        readiness = self.dist / "release-readiness.md"
        readiness.write_text(f"Status: pass\nVersion `{version}`\nCommit `{full_commit}`\n", encoding="utf-8")
        (self.dist / "sbom.spdx.json").write_text(json.dumps({"name": f"ProvidAPT {version}"}), encoding="utf-8")
        (self.dist / "sbom.cdx.json").write_text(json.dumps({"metadata": {"component": {"version": version}}}), encoding="utf-8")
        scan = self.write_json("security/scan-manifest.json", {
            "schema": "providapt.security_scan_manifest.v1",
            "full_commit": full_commit,
            "version": version,
            "reports": {"govulncheck_json": "present", "grype_source": "present", "trivy_fs": "present"},
        })
        signing = self.write_json("artifact/artifact-signing-gate.json", {
            "status": "pass",
            "artifact_count": 4,
            "signature": {"format": "providapt-ed25519"},
        })
        values = {
            "dist_dir": str(self.dist),
            "release_readiness": str(readiness),
            "scan_manifest": str(scan),
            "artifact_signing_gate": str(signing),
            "version": version,
            "commit": short_commit,
            "full_commit": full_commit,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_passes_consistent_release_evidence(self):
        report = subject.build_report(self.args())
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["sbom"]["spdx_count"], 1)
        self.assertIn("Release Evidence Consistency", subject.render_markdown(report))

    def test_blocks_commit_mismatch(self):
        scan = self.write_json("bad-scan.json", {
            "schema": "providapt.security_scan_manifest.v1",
            "full_commit": "b" * 40,
            "version": "v1.2.3",
            "reports": {"govulncheck_json": "present"},
        })
        report = subject.build_report(self.args(scan_manifest=str(scan)))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("scan manifest commit mismatch", "\n".join(report["failures"]))

    def test_blocks_missing_sbom_and_readiness(self):
        empty_dist = self.tmp / "empty-dist"
        empty_dist.mkdir()
        report = subject.build_report(self.args(
            dist_dir=str(empty_dist),
            release_readiness=str(empty_dist / "missing.md"),
        ))
        self.assertEqual(report["status"], "blocked")
        text = "\n".join(report["failures"])
        self.assertIn("release readiness report is missing", text)
        self.assertIn("SPDX SBOM is missing", text)


if __name__ == "__main__":
    unittest.main()
