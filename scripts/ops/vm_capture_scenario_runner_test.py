import importlib.util
import json
import shutil
import subprocess
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("vm-capture-scenario-runner.py")
SPEC = importlib.util.spec_from_file_location("vm_capture_scenario_runner", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class VMCaptureScenarioRunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-vm-capture-scenario-runner-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_build_remote_script_contains_all_expected_scenarios(self):
        script = subject.build_remote_script("http://vm-ubuntu-master:18080", "providapt-test")

        self.assertIn("record shell_activity", script)
        self.assertIn("record file_mutation", script)
        self.assertIn("record network_activity", script)
        self.assertIn("record process_chain", script)
        self.assertIn("record permission_change", script)
        self.assertIn("scenario=%s status=pass", script)
        self.assertIn("curl -fsS --max-time 3", script)
        self.assertIn("chmod 640", script)

    def test_run_host_records_passed_scenarios(self):
        calls = []

        def runner(cmd, timeout):
            calls.append(cmd)
            return subprocess.CompletedProcess(
                cmd,
                0,
                "\n".join([
                    "scenario=shell_activity status=pass",
                    "scenario=file_mutation status=pass",
                    "scenario=network_activity status=pass",
                    "scenario=process_chain status=pass",
                    "scenario=permission_change status=pass",
                ]) + "\n",
                "",
            )

        result = subject.run_host(
            "ubuntu@vm-ubuntu-master",
            "http://vm-ubuntu-master:18080",
            "providapt-test",
            10,
            runner,
        )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(set(result["scenario_statuses"]), set(subject.SCENARIOS))
        self.assertTrue(all(value == "pass" for value in result["scenario_statuses"].values()))
        self.assertEqual(calls[0][0], "ssh")

    def test_build_report_blocks_missing_scenario(self):
        def runner(cmd, timeout):
            return subprocess.CompletedProcess(
                cmd,
                0,
                "scenario=shell_activity status=pass\n",
                "",
            )

        report = subject.build_report(Namespace(
            host=["ubuntu@vm-ubuntu-master"],
            server_url="http://vm-ubuntu-master:18080",
            marker_prefix="providapt-test",
            timeout_seconds=10,
            out_dir=str(self.tmp),
        ), runner)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("missing scenario", "\n".join(report["failures"]))

    def test_write_outputs_creates_json_and_markdown(self):
        report = {
            "schema": subject.SCHEMA,
            "status": "pass",
            "generated_at": "2026-09-05T00:00:00+00:00",
            "hosts": [{
                "host": "ubuntu@vm-ubuntu-master",
                "status": "pass",
                "scenario_statuses": {name: "pass" for name in subject.SCENARIOS},
                "marker": "providapt-test",
                "failures": [],
            }],
            "failures": [],
        }

        subject.write_outputs(report, self.tmp)

        saved = json.loads((self.tmp / "vm-capture-scenarios.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "pass")
        rendered = (self.tmp / "vm-capture-scenarios.md").read_text(encoding="utf-8")
        self.assertIn("VM Capture Scenario Runner", rendered)
        self.assertIn("permission_change", rendered)


if __name__ == "__main__":
    unittest.main()
