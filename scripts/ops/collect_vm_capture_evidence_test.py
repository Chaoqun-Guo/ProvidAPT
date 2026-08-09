import importlib.util
import json
import shutil
import subprocess
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("collect-vm-capture-evidence.py")
SPEC = importlib.util.spec_from_file_location("collect_vm_capture_evidence", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class CollectVMCaptureEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-vm-capture-evidence-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_collect_host_copies_listed_files(self):
        def runner(cmd, timeout):
            if cmd[0] == "ssh":
                if "ls -1t" in cmd[-1]:
                    return subprocess.CompletedProcess(cmd, 0, "/var/log/providapt/providapt-a.ndjson\n", "")
                if "net_" in cmd[-1]:
                    return subprocess.CompletedProcess(cmd, 0, '{"type":"net_connect","process":{"pid":1,"ppid":1,"uid":0,"gid":0},"payload":{"saddr":1,"daddr":2,"sport":3,"dport":4,"protocol":6}}\n', "")
                return subprocess.CompletedProcess(cmd, 0, '{"type":"process_exec"}\n', "")
            raise AssertionError(cmd)

        report = subject.collect_host("ubuntu@vm-ubuntu-master", "/var/log/providapt", self.tmp, 5, 5, 100, 20, runner)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(len(report["copied_files"]), 2)

    def test_build_report_blocks_missing_files(self):
        def runner(cmd, timeout):
            return subprocess.CompletedProcess(cmd, 0, "", "")

        report = subject.build_report(Namespace(
            host=["ubuntu@vm-ubuntu-master"],
            remote_dir="/var/log/providapt",
            out_dir=str(self.tmp),
            timeout_seconds=5,
            gate_timeout_seconds=30,
            max_files=5,
            lines_per_file=100,
            network_lines=20,
            skip_gate=True,
        ), runner)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("no event", "\n".join(report["failures"]))

    def test_run_capture_gate_invokes_existing_gate(self):
        host_dir = self.tmp / "ubuntu_vm"
        host_dir.mkdir()
        (host_dir / "providapt-a.ndjson").write_text('{"type":"process_exec"}\n', encoding="utf-8")

        def runner(cmd, timeout):
            report = {"status": "pass"}
            Path(cmd[cmd.index("--out-json") + 1]).write_text(json.dumps(report), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "ok", "")

        result = subject.run_capture_gate(self.tmp, 5, runner)
        self.assertEqual(result["report"]["status"], "pass")


if __name__ == "__main__":
    unittest.main()
