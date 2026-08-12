import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("customer-environment-certification-gate.py")
SPEC = importlib.util.spec_from_file_location("customer_environment_certification_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class CustomerEnvironmentCertificationGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-customer-certification-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, data):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def args(self, **overrides):
        rbac = self.write_json("rbac.json", {"status": "pass", "tenant_count": 2, "tenant_scoped_keys": 2, "custom_role_count": 1})
        policy = self.write_json("policy.json", {"status": "pass"})
        siem = self.write_json("siem.json", {"status": "pass", "delivered": 3, "dead_letter": 0})
        siem_cert = self.write_json("siem-cert.json", {"status": "pass", "field_mapping": "verified", "retry": "verified", "backpressure": "verified", "alert_landing": "verified"})
        upgrade = self.write_json("upgrade.json", {"status": "planned", "target_version": "v1", "eligible_agents": 3, "batches": [{"name": "canary", "agents": ["a1"], "pause_after": True}], "pause_resume_controls": {"pause": "p"}, "rollback": {"batches": [{"name": "canary"}]}})
        soak = self.write_json("soak.json", {"status": "pass", "checks": {"duration": {"observed": 25}, "drops": {"observed": 0}}})
        prod = self.write_json("prod.json", {"status": "pass"})
        deploy = self.write_json("deploy.json", {"status": "pass", "tls_enabled": True, "control_plane_state_backend": "postgres://db"})
        backup = self.write_json("backup.json", {"status": "pass"})
        plugin = self.write_json("plugin.json", {"status": "pass", "signature_present": True, "plugin": {"name": "p", "permissions": ["alerts:read"]}})
        onboarding = self.write_json("onboarding.json", {"mode": "standalone", "environment_checks": [{"name": "tailscale"}, {"name": "ssh"}, {"name": "api"}, {"name": "tls"}, {"name": "postgres"}]})
        role_review = self.tmp / "role-review.md"
        role_review.write_text("admin approved by Alice Owner\nanalyst approved by Sam Reviewer\n", encoding="utf-8")
        audit_export = self.tmp / "audit.csv"
        audit_export.write_text("id,timestamp,actor,action\n1,2026-08-12T00:00:00Z,Alice,policy.publish\n", encoding="utf-8")
        values = {
            "rbac_audit": rbac,
            "policy_approval_gate": policy,
            "audit_export": str(audit_export),
            "role_review": str(role_review),
            "require_delegated_admin": True,
            "require_audit_export": True,
            "require_role_review": True,
            "min_tenants": 2,
            "min_tenant_scoped_keys": 2,
            "min_audit_export_rows": 1,
            "siem_verify": siem,
            "siem_certification": siem_cert,
            "require_siem_certification": True,
            "min_siem_delivered": 1,
            "max_siem_dead_letter": 0,
            "upgrade_rollout": upgrade,
            "require_agent_groups": True,
            "soak_readiness": soak,
            "min_soak_hours": 24,
            "max_dropped_events": 0,
            "production_readiness_gate": prod,
            "deployment_diagnostics_gate": deploy,
            "backup_readiness_gate": backup,
            "require_tls": True,
            "require_state_backend": True,
            "plugin_gate": plugin,
            "require_plugin_gate": True,
            "require_plugin_signature": True,
            "require_plugin_permissions": True,
            "onboarding_manifest": onboarding,
            "min_onboarding_checks": 5,
            "required_onboarding_check": ["tailscale", "ssh", "api"],
        }
        values.update(overrides)
        return Namespace(**values)

    def test_passes_complete_customer_certification_evidence(self):
        report = subject.build_report(self.args())
        self.assertEqual(report["status"], "pass")
        self.assertFalse(report["warnings"])
        self.assertFalse(report["failures"])

    def test_blocks_missing_siem_certification_and_short_soak(self):
        short_soak = self.write_json("short-soak.json", {"status": "pass", "checks": {"duration": {"observed": 2}, "drops": {"observed": 0}}})
        report = subject.build_report(self.args(siem_certification="", soak_readiness=short_soak))
        self.assertEqual(report["status"], "blocked")
        text = "\n".join(report["failures"])
        self.assertIn("target SIEM/SOAR certification evidence is missing", text)
        self.assertIn("soak duration", text)

    def test_blocks_empty_audit_export(self):
        empty_audit = self.tmp / "empty-audit.csv"
        empty_audit.write_text("id,timestamp\n", encoding="utf-8")
        report = subject.build_report(self.args(audit_export=str(empty_audit)))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("audit export has no audit records", "\n".join(report["failures"]))

    def test_blocks_pending_role_review(self):
        pending_review = self.tmp / "pending-role-review.md"
        pending_review.write_text("admin pending delegate approval\n", encoding="utf-8")
        report = subject.build_report(self.args(role_review=str(pending_review)))
        self.assertEqual(report["status"], "blocked")
        text = "\n".join(report["failures"])
        self.assertIn("role review contains unresolved", text)
        self.assertIn("role review has no approved role entries", text)


if __name__ == "__main__":
    unittest.main()
