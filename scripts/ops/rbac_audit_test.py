import importlib.util
import json
import shutil
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("rbac-audit.py")
SPEC = importlib.util.spec_from_file_location("rbac_audit", SCRIPT)
rbac = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(rbac)


class RBACAuditTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-rbac-audit-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_warns_for_unscoped_non_admin(self):
        config = rbac.load_toml(self.write_config("""
[api]
auth_enabled = true
auth_keys = ["admin-key", "analyst-key"]
auth_roles = { "admin-key" = "admin", "analyst-key" = "analyst" }
auth_identities = { "admin-key" = "ops", "analyst-key" = "soc" }
"""))
        report = rbac.audit_config(config, self.tmp / "providapt.toml")
        self.assertEqual(report["status"], "warn")
        self.assertTrue(any("no tenant scope" in item for item in report["warnings"]))

    def test_blocks_disabled_auth_and_wildcard(self):
        config = rbac.load_toml(self.write_config("""
[api]
auth_enabled = false
auth_keys = ["operator-key"]
auth_roles = { "operator-key" = "operator" }
auth_permissions = { operator = ["*"] }
"""))
        report = rbac.audit_config(config, self.tmp / "providapt.toml")
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any("auth_enabled" in item for item in report["failures"]))
        self.assertTrue(any("wildcard" in item for item in report["failures"]))

    def write_config(self, text):
        path = self.tmp / "providapt.toml"
        path.write_text(text.strip() + "\n", encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
