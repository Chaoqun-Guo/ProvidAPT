import base64
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("artifact-signing-gate.py")
SPEC = importlib.util.spec_from_file_location("artifact_signing_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = subject
SPEC.loader.exec_module(subject)


class ArtifactSigningGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-artifact-signing-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir(parents=True)
        self.dist = self.tmp / "dist"
        self.dist.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_artifact(self, name, data):
        path = self.dist / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def write_checksums(self, artifacts):
        lines = []
        for name, path in artifacts.items():
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
        checksums = self.dist / "checksums.txt"
        checksums.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return checksums

    def write_providapt_signature(self, checksums):
        bundle = {
            "type": "providapt-ed25519-checksums-v1",
            "algorithm": "ed25519",
            "created_at": "2026-08-01T00:00:00Z",
            "message_sha256": hashlib.sha256(checksums.read_bytes()).hexdigest(),
            "public_key": "11" * 32,
            "signature": base64.b64encode(b"\x22" * 64).decode("ascii"),
        }
        signature = self.dist / "checksums.txt.sig"
        signature.write_text(json.dumps(bundle), encoding="utf-8")
        return signature

    def args(self, checksums=None, signature=None, required_artifact=None):
        return Namespace(
            dist_dir=str(self.dist),
            checksums=str(checksums or self.dist / "checksums.txt"),
            signature=str(signature or self.dist / "checksums.txt.sig"),
            required_artifact=required_artifact or [],
            out_json=str(self.tmp / "out.json"),
            out_md=str(self.tmp / "out.md"),
        )

    def test_passes_with_matching_checksums_and_providapt_signature(self):
        artifacts = {
            "providapt-linux-amd64.tar.gz": self.write_artifact("providapt-linux-amd64.tar.gz", b"archive"),
            "providapt_1.0.0_amd64.deb": self.write_artifact("providapt_1.0.0_amd64.deb", b"deb"),
        }
        checksums = self.write_checksums(artifacts)
        signature = self.write_providapt_signature(checksums)
        report = subject.build_report(self.args(checksums, signature, ["archive", "deb"]))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["signature"]["format"], "providapt-ed25519")
        self.assertEqual(report["artifact_count"], 2)

    def test_blocks_on_checksum_mismatch(self):
        artifact = self.write_artifact("providapt.tar.gz", b"archive")
        checksums = self.write_checksums({"providapt.tar.gz": artifact})
        checksums.write_text("0" * 64 + "  providapt.tar.gz\n", encoding="utf-8")
        signature = self.write_providapt_signature(checksums)
        report = subject.build_report(self.args(checksums, signature))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("checksum mismatch: providapt.tar.gz", report["failures"])

    def test_blocks_path_traversal_in_checksums(self):
        checksums = self.dist / "checksums.txt"
        checksums.write_text("0" * 64 + "  ../escape.tar.gz\n", encoding="utf-8")
        signature = self.write_providapt_signature(checksums)
        report = subject.build_report(self.args(checksums, signature))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("unsafe artifact path", "\n".join(report["failures"]))

    def test_blocks_missing_signature(self):
        artifact = self.write_artifact("providapt.tar.gz", b"archive")
        checksums = self.write_checksums({"providapt.tar.gz": artifact})
        report = subject.build_report(self.args(checksums, self.dist / "missing.sig"))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("signature evidence missing", "\n".join(report["failures"]))

    def test_cli_writes_reports_and_returns_zero_on_pass(self):
        artifact = self.write_artifact("providapt.tar.gz", b"archive")
        checksums = self.write_checksums({"providapt.tar.gz": artifact})
        signature = self.write_providapt_signature(checksums)
        out_json = self.tmp / "gate.json"
        out_md = self.tmp / "gate.md"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--dist-dir",
                str(self.dist),
                "--checksums",
                str(checksums),
                "--signature",
                str(signature),
                "--out-json",
                str(out_json),
                "--out-md",
                str(out_md),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(out_json.read_text(encoding="utf-8"))["status"], "pass")
        self.assertIn("Artifact Signing Gate", out_md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
