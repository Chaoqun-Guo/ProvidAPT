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
        ))
        self.assertEqual(manifest["schema"], onboarding.SCHEMA)
        config = (self.tmp / "providapt.onboarding.yaml").read_text(encoding="utf-8")
        self.assertIn("postgres://providapt", config)
        self.assertIn("auth_enabled: true", config)
        loaded = json.loads((self.tmp / "onboarding-manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(loaded["postgres"])
        check_names = {item["name"] for item in loaded["environment_checks"]}
        self.assertIn("tailscale", check_names)
        self.assertIn("ssh", check_names)
        self.assertIn("api", check_names)
        self.assertIn("postgres", check_names)


if __name__ == "__main__":
    unittest.main()
