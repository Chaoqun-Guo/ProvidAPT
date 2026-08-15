#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import sys
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("release-security-local-gate.py")
spec = importlib.util.spec_from_file_location("release_security_local_gate", SCRIPT)
assert spec and spec.loader
subject = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = subject
spec.loader.exec_module(subject)


class ReleaseSecurityLocalGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path.cwd() / ".tmp-release-security-local-gate-test"
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()
        self.security = self.root / "security"
        self.old_path = os.environ.get("PATH", "")

    def tearDown(self) -> None:
        os.environ["PATH"] = self.old_path
        if self.root.exists():
            shutil.rmtree(self.root)

    def args(self) -> Namespace:
        return Namespace(
            project_dir=str(self.project),
            security_dir=str(self.security),
            version="v-test",
            commit="abc123",
            full_commit="abc123def456",
            go_tags="bpf",
            timeout=20,
            skip_govulncheck=False,
            skip_grype=False,
            skip_trivy=False,
            allow_partial=False,
            out_json=str(self.security / "release-security-local-gate.json"),
            out_md=str(self.security / "release-security-local-gate.md"),
        )

    def write_tool(self, name: str, body: str) -> None:
        tool_dir = self.root / "bin"
        tool_dir.mkdir(exist_ok=True)
        path = tool_dir / name
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        os.environ["PATH"] = f"{tool_dir}:{self.old_path}"

    def test_missing_tools_are_recorded_as_attempts(self) -> None:
        os.environ["PATH"] = str(self.root / "empty-bin")
        report = subject.build_report(self.args())

        self.assertEqual(report["status"], "blocked")
        self.assertIn("govulncheck_json", report["blocked"])
        attempt = json.loads((self.security / "govulncheck-attempt.json").read_text(encoding="utf-8"))
        self.assertEqual(attempt["status"], "missing_tool")
        self.assertIn("Install missing scanners", report["next_actions"][0])

    def test_fake_scanners_produce_passing_manifest(self) -> None:
        self.write_tool(
            "govulncheck",
            "if [ \"$1\" = \"-json\" ]; then printf '{\"ok\":true}\\n'; else printf 'No vulnerabilities found.\\n'; fi\n",
        )
        self.write_tool("grype", "printf '{\"matches\":[]}\\n'\n")
        self.write_tool(
            "trivy",
            "out=''\nwhile [ $# -gt 0 ]; do if [ \"$1\" = '--output' ]; then shift; out=\"$1\"; fi; shift; done\nprintf '{\"Results\":[]}\\n' > \"$out\"\n",
        )

        report = subject.build_report(self.args())
        manifest = json.loads((self.security / "scan-manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(report["status"], "pass")
        self.assertEqual(manifest["status"], "pass")
        self.assertEqual(report["blocked"], [])


if __name__ == "__main__":
    unittest.main()
