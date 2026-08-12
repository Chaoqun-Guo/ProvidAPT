#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("security-scan-manifest.py")
spec = importlib.util.spec_from_file_location("security_scan_manifest", SCRIPT)
assert spec and spec.loader
subject = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = subject
spec.loader.exec_module(subject)


class SecurityScanManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path.cwd() / ".tmp-security-scan-manifest-test"
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir()

    def tearDown(self) -> None:
        if self.root.exists():
            shutil.rmtree(self.root)

    def args(self) -> Namespace:
        return Namespace(
            security_dir=str(self.root),
            version="v-test",
            commit="abc123",
            full_commit="abc123def456",
            allow_partial=False,
            out_json=str(self.root / "scan-manifest.json"),
            out_md=str(self.root / "scan-manifest.md"),
        )

    def test_manifest_blocks_missing_reports(self) -> None:
        (self.root / "govulncheck.txt").write_text("No vulnerabilities found.\n", encoding="utf-8")
        (self.root / "govulncheck.json").write_text("{}\n", encoding="utf-8")

        report = subject.build_report(self.args())

        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["reports"]["govulncheck_json"], "present")
        self.assertIn("grype_source", report["missing_reports"])
        self.assertIn("trivy_fs", report["missing_reports"])

    def test_manifest_passes_when_all_reports_are_present(self) -> None:
        for filename in subject.REPORTS.values():
            (self.root / filename).write_text(json.dumps({"ok": True}) + "\n", encoding="utf-8")

        report = subject.build_report(self.args())

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["missing_reports"], [])

    def test_manifest_flags_invalid_json(self) -> None:
        for filename in subject.REPORTS.values():
            (self.root / filename).write_text("{}\n", encoding="utf-8")
        (self.root / "trivy-fs.json").write_text("{broken\n", encoding="utf-8")

        report = subject.build_report(self.args())
        rendered = subject.render_markdown(report)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("trivy_fs", report["invalid_reports"])
        self.assertIn("Invalid Reports", rendered)

    def test_manifest_accepts_json_streams(self) -> None:
        for filename in subject.REPORTS.values():
            (self.root / filename).write_text('{"a": 1}\n{\n  "b": 2\n}\n', encoding="utf-8")

        report = subject.build_report(self.args())

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["invalid_reports"], [])

    def test_manifest_includes_scanner_attempts(self) -> None:
        (self.root / "govulncheck.txt").write_text("No vulnerabilities found.\n", encoding="utf-8")
        (self.root / "govulncheck.json").write_text("{}\n", encoding="utf-8")
        (self.root / "grype-source-attempt.json").write_text(json.dumps({
            "status": "blocked",
            "exit_code": 124,
            "duration_seconds": 300,
            "error": "vulnerability DB download timed out",
        }) + "\n", encoding="utf-8")

        report = subject.build_report(self.args())
        rendered = subject.render_markdown(report)

        self.assertEqual(report["scanner_attempts"]["grype_source"]["status"], "blocked")
        self.assertEqual(report["scanner_attempts"]["grype_source"]["exit_code"], 124)
        self.assertIn("Scanner Attempts", rendered)
        self.assertIn("vulnerability DB download timed out", rendered)


if __name__ == "__main__":
    unittest.main()
