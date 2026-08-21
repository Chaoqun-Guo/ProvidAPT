import importlib.util
import json
import shutil
import sys
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("onboarding-wizard.py")
SPEC = importlib.util.spec_from_file_location("onboarding_wizard", SCRIPT)
onboarding = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = onboarding
SPEC.loader.exec_module(onboarding)


class OnboardingWizardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-onboarding-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_writes_config_checklist_and_manifest(self):
        manifest = onboarding.build_bundle(Namespace(
            out_dir=str(self.tmp),
            mode="standalone",
            rest_port=18080,
            grpc_port=50051,
            log_dir="/var/log/providapt",
            log_retain_bytes=268435456,
            alert_retain_bytes=67108864,
            postgres_dsn="postgres://providapt:pw@db/providapt",
            server_url="http://vm-ubuntu-master:18080/",
            policy_endpoint="http://vm-ubuntu-master:18080",
            vm_hosts="ubuntu@vm-ubuntu-master centos@vm-centos-slave",
            check_results="",
        ))
        self.assertEqual(manifest["schema"], onboarding.SCHEMA)
        config = (self.tmp / "providapt.onboarding.yaml").read_text(encoding="utf-8")
        self.assertIn("postgres://providapt", config)
        self.assertIn("auth_enabled: true", config)
        self.assertIn("endpoint: http://vm-ubuntu-master:18080", config)
        loaded = json.loads((self.tmp / "onboarding-manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(loaded["postgres"])
        self.assertEqual(loaded["status"], "warn")
        self.assertEqual(loaded["server_url"], "http://vm-ubuntu-master:18080")
        self.assertEqual(loaded["policy_endpoint"], "http://vm-ubuntu-master:18080")
        self.assertIn("report", loaded["outputs"])
        self.assertIn("check_results_template", loaded["outputs"])
        self.assertIn("operator_flow", loaded["outputs"])
        self.assertEqual(len(loaded["operator_flow"]), 5)
        self.assertEqual(loaded["operator_flow"][-1]["status"], "pending")
        self.assertIn("ubuntu@vm-ubuntu-master", loaded["environment_checks"][1]["command"])
        self.assertIn("http://vm-ubuntu-master:18080/api/v1/status", loaded["environment_checks"][2]["command"])
        self.assertTrue(loaded["next_actions"])
        self.assertEqual(loaded["action_summary"]["action_count"], len(loaded["next_actions"]))
        self.assertIn("api", loaded["action_summary"]["unknown_checks"])
        check_names = {item["name"] for item in loaded["environment_checks"]}
        self.assertIn("tailscale", check_names)
        self.assertIn("ssh", check_names)
        self.assertIn("api", check_names)
        self.assertIn("dashboard", check_names)
        self.assertIn("postgres", check_names)
        self.assertTrue(all(item.get("severity") for item in loaded["environment_checks"]))
        self.assertTrue(all(item.get("next_step") for item in loaded["environment_checks"]))
        checklist = (self.tmp / "onboarding-checklist.md").read_text(encoding="utf-8")
        self.assertIn("Next:", checklist)
        self.assertIn("dashboard", checklist)
        report = (self.tmp / "onboarding-report.md").read_text(encoding="utf-8")
        self.assertIn("ProvidAPT Onboarding Report", report)
        self.assertIn("Action Summary", report)
        self.assertIn("Next Actions", report)
        flow = (self.tmp / "onboarding-operator-flow.md").read_text(encoding="utf-8")
        self.assertIn("First-Run Operator Flow", flow)
        self.assertIn("Prepare environment", flow)
        self.assertIn(f"providaptd -config {self.tmp}/providapt.onboarding.yaml", flow)
        self.assertIn("PROVIDAPT_SERVER_URL=http://vm-ubuntu-master:18080", flow)
        self.assertIn("ONBOARDING_VM_HOSTS='ubuntu@vm-ubuntu-master centos@vm-centos-slave'", flow)
        template = json.loads((self.tmp / "onboarding-check-results.template.json").read_text(encoding="utf-8"))
        self.assertEqual(template["schema"], "providapt.onboarding_check_results.v1")
        self.assertIn("command", template["checks"][0])

    def test_merges_check_results_into_onboarding_report(self):
        results = self.tmp / "results.json"
        results.write_text(json.dumps({
            "checks": [
                {"name": "tailscale", "status": "pass", "observed": "3 peers online", "evidence": "tailscale status"},
                {"name": "api", "status": "fail", "observed": "connection refused"},
                {"name": "tls", "status": "warn", "observed": "lab cert expires soon"},
            ]
        }), encoding="utf-8")
        manifest = onboarding.build_bundle(Namespace(
            out_dir=str(self.tmp),
            mode="standalone",
            rest_port=18080,
            grpc_port=50051,
            log_dir="/var/log/providapt",
            log_retain_bytes=268435456,
            alert_retain_bytes=67108864,
            postgres_dsn="",
            server_url="",
            policy_endpoint="",
            vm_hosts="",
            check_results=str(results),
        ))
        self.assertEqual(manifest["status"], "blocked")
        self.assertEqual(manifest["check_summary"]["fail"], 1)
        self.assertEqual(manifest["next_actions"][0]["check"], "api")
        self.assertEqual(manifest["action_summary"]["blocked_checks"], ["api"])
        self.assertEqual(manifest["action_summary"]["warning_checks"], ["tls"])
        self.assertIn("ssh", manifest["action_summary"]["unknown_checks"])
        api = next(item for item in manifest["environment_checks"] if item["name"] == "api")
        self.assertEqual(api["status"], "fail")
        self.assertEqual(api["observed"], "connection refused")
        report = (self.tmp / "onboarding-report.md").read_text(encoding="utf-8")
        self.assertIn("connection refused", report)
        self.assertIn("3 peers online", report)
        self.assertIn("| fail | api |", report)
        self.assertIn("| warn | tls |", report)
        self.assertIn("Start providaptd", report)
        self.assertIn("Operator Flow", report)

    def test_server_url_is_trimmed_and_used_in_operator_flow(self):
        manifest = onboarding.build_bundle(Namespace(
            out_dir=str(self.tmp),
            mode="standalone",
            rest_port=18080,
            grpc_port=50051,
            log_dir="/var/log/providapt",
            log_retain_bytes=268435456,
            alert_retain_bytes=67108864,
            postgres_dsn="",
            server_url="http://control.example:18080/",
            policy_endpoint="http://policy.example:18080",
            vm_hosts="",
            check_results="",
        ))
        self.assertEqual(manifest["server_url"], "http://control.example:18080")
        self.assertEqual(manifest["policy_endpoint"], "http://policy.example:18080")
        flow = (self.tmp / "onboarding-operator-flow.md").read_text(encoding="utf-8")
        self.assertIn("curl -fsS http://control.example:18080/api/v1/status", flow)
        self.assertIn("PROVIDAPT_SERVER_URL=http://control.example:18080", flow)
        self.assertIn("POLICY_ENDPOINT=http://policy.example:18080", flow)
        config = (self.tmp / "providapt.onboarding.yaml").read_text(encoding="utf-8")
        self.assertIn("endpoint: http://policy.example:18080", config)


if __name__ == "__main__":
    unittest.main()
