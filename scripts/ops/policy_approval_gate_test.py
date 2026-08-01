import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("policy-approval-gate.py")
SPEC = importlib.util.spec_from_file_location("policy_approval_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class PolicyApprovalGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-policy-approval-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def args(self, **overrides):
        values = {
            "rbac_audit": str(self.write_json("rbac.json", {"status": "pass", "tenant_scoped_keys": 2, "tenant_count": 2})),
            "compliance_status": str(self.write_json("compliance.json", {"approvals": {
                "enabled": True,
                "required_actions": subject.DEFAULT_REQUIRED_ACTIONS,
                "history": [{"id": "appr-1", "status": "approved", "action": "policy.publish"}],
            }})),
            "audit_log": str(self.write_json("audit.json", {"entries": [{"source": "policy", "message": "approval consumed"}]})),
            "required_action": [],
            "min_tenant_scoped_keys": 1,
            "min_tenants": 1,
            "require_audit_log": True,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_passes_with_rbac_approvals_and_audit(self):
        report = subject.build_report(self.args())
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["tenant_count"], 2)
        self.assertEqual(report["audit_matches"], 1)

    def test_blocks_missing_required_approval_action(self):
        compliance = self.write_json("compliance-missing.json", {"approvals": {"enabled": True, "required_actions": ["policy.publish"]}})
        report = subject.build_report(self.args(compliance_status=str(compliance), require_audit_log=False))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("missing required actions", "\n".join(report["failures"]))

    def test_blocks_unscoped_tenants(self):
        rbac = self.write_json("rbac-low.json", {"status": "pass", "tenant_scoped_keys": 0, "tenant_count": 0})
        report = subject.build_report(self.args(rbac_audit=str(rbac), require_audit_log=False))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("tenant-scoped keys", "\n".join(report["failures"]))


if __name__ == "__main__":
    unittest.main()
