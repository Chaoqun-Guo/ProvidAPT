import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("onboarding-wizard.py")
SPEC = importlib.util.spec_from_file_location("onboarding_wizard", SCRIPT)
onboarding = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
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
            check_results="",
        ))
        self.assertEqual(manifest["schema"], onboarding.SCHEMA)
        config = (self.tmp / "providapt.onboarding.yaml").read_text(encoding="utf-8")
        self.assertIn("postgres://providapt", config)
        self.assertIn("auth_enabled: true", config)
        loaded = json.loads((self.tmp / "onboarding-manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(loaded["postgres"])
        self.assertEqual(loaded["status"], "warn")
        self.assertIn("report", loaded["outputs"])
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

    def test_merges_check_results_into_onboarding_report(self):
        results = self.tmp / "results.json"
        results.write_text(json.dumps({
            "checks": [
                {"name": "tailscale", "status": "pass", "observed": "3 peers online", "evidence": "tailscale status"},
                {"name": "api", "status": "fail", "observed": "connection refused"},
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
            check_results=str(results),
        ))
        self.assertEqual(manifest["status"], "blocked")
        self.assertEqual(manifest["check_summary"]["fail"], 1)
        api = next(item for item in manifest["environment_checks"] if item["name"] == "api")
        self.assertEqual(api["status"], "fail")
        self.assertEqual(api["observed"], "connection refused")
        report = (self.tmp / "onboarding-report.md").read_text(encoding="utf-8")
        self.assertIn("connection refused", report)
        self.assertIn("3 peers online", report)


if __name__ == "__main__":
    unittest.main()
