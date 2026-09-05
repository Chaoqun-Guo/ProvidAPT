import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("security-hardening-pack.py")
SPEC = importlib.util.spec_from_file_location("security_hardening_pack", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class SecurityHardeningPackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-security-hardening-pack-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_generates_open_source_security_pack(self):
        gate = self.tmp / "gate.json"
        gate.write_text(json.dumps({"status": "warn", "sections": {"systemd_sandbox": {"status": "pass"}, "configuration": {"status": "warn"}}}), encoding="utf-8")
        report = subject.build_pack(Namespace(
            hardening_gate=str(gate),
            tailscale_acl="examples/security/tailscale-acl-example.json",
            out_json=str(self.tmp / "pack.json"),
            out_md=str(self.tmp / "pack.md"),
        ))
        self.assertEqual(report["schema"], subject.SCHEMA)
        self.assertEqual(report["status"], "warn")
        for section in ["systemd", "firewall", "tailscale_acl", "tls", "secret_permissions", "log_redaction", "sbom_scans"]:
            self.assertIn(section, report["checks"])
            self.assertTrue(report["checks"][section]["recommendations"])
        rendered = subject.render_markdown(report)
        self.assertIn("Open Source Security Hardening Pack", rendered)
        self.assertIn("Tailscale ACL", rendered)


if __name__ == "__main__":
    unittest.main()
