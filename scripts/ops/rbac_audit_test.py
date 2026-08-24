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

    def test_warns_when_trusted_header_sso_is_absent(self):
        config = rbac.load_toml(self.write_config("""
[api]
auth_permissions = { operator = ["GET:/api/v1/control/fleet"] }
"""))
        report = rbac.audit_config(config, self.tmp / "providapt.toml")
        self.assertEqual(report["status"], "warn")
        self.assertTrue(any("trusted-header SSO" in item for item in report["warnings"]))
        self.assertEqual(report["key_count"], 0)
        self.assertIn("open-source", json.dumps(report))

    def test_blocks_unrestricted_custom_permission(self):
        config = rbac.load_toml(self.write_config("""
[api]
auth_permissions = { operator = ["*"] }
"""))
        report = rbac.audit_config(config, self.tmp / "providapt.toml")
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any("wildcard" in item for item in report["failures"]))

    def test_reports_trusted_header_sso(self):
        config = rbac.load_toml(self.write_config("""
[sso]
trusted_header_auth = true
user_header = "X-Forwarded-User"
role_header = "X-Forwarded-Role"
tenant_header = "X-Forwarded-Tenant"
"""))
        report = rbac.audit_config(config, self.tmp / "providapt.toml")
        self.assertEqual(report["status"], "pass")
        self.assertTrue(report["trusted_header_sso"])
        self.assertEqual(report["tenant_count"], 0)
        self.assertIn("open-source", rbac.render_markdown(report))

    def write_config(self, text):
        path = self.tmp / "providapt.toml"
        path.write_text(text.strip() + "\n", encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
