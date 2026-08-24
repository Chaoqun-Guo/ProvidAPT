import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("vm-open-source-residue.py")


class VMOpenSourceResidueTest(unittest.TestCase):
    def test_blocks_legacy_auth_residue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "vm.txt"
            snapshot.write_text(
                "root 2018 providapt-auth-server /providapt-auth-server\n"
                "30-api-auth.conf\n"
                "90-api-key-rotation.conf\n",
                encoding="utf-8",
            )
            out_json = root / "report.json"
            out_md = root / "report.md"
            proc = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--snapshot",
                    str(snapshot),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            report = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "blocked")
            self.assertIn("providapt-auth-server", report["hosts"][0]["findings"])
            self.assertIn("30-api-auth.conf", report["hosts"][0]["findings"])
            self.assertIn("Stop and disable", out_md.read_text(encoding="utf-8"))

    def test_passes_clean_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "vm.txt"
            snapshot.write_text("root 42 providaptd /usr/local/sbin/providaptd\n", encoding="utf-8")
            out_json = root / "report.json"
            out_md = root / "report.md"
            proc = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--snapshot",
                    str(snapshot),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            report = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "pass")


if __name__ == "__main__":
    unittest.main()
