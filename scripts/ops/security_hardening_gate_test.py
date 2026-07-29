import importlib.util
import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).with_name("security-hardening-gate.py")
SPEC = importlib.util.spec_from_file_location("security_hardening_gate", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(gate)


class SecurityHardeningGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-security-hardening-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_warns_but_allows_ebpf_approved_systemd_relaxations(self):
        config = self.write("providapt.yaml", "auth_enabled: true\nenable: true\nencrypt: true\nrequire_approvals: true\nredact_archives: true\n")
        service = self.write("providapt.service", "PrivateTmp=true\nProtectHome=true\nRuntimeDirectory=providapt\nReadWritePaths=/var/log/providapt\nCapabilityBoundingSet=CAP_BPF\nNoNewPrivileges=false\n")
        env_file = self.write("providapt.env", 'PROVIDAPT_SKIP_PRIVILEGE_DROP=""\nPROVIDAPT_SKIP_SANITY_CHECKS=""\n')
        args = SimpleNamespace(config=str(config), service=str(service), env_file=str(env_file), rbac_audit="")

        report = gate.build_report(args)

        self.assertEqual(report["status"], "warn")
        self.assertEqual(report["sections"]["configuration"]["status"], "pass")

    def test_blocks_missing_auth_and_tls(self):
        config = self.write("providapt.yaml", "encrypt: true\n")
        service = self.write("providapt.service", "")
        env_file = self.write("providapt.env", "")
        args = SimpleNamespace(config=str(config), service=str(service), env_file=str(env_file), rbac_audit="")

        report = gate.build_report(args)

        self.assertEqual(report["status"], "blocked")

    def write(self, name, content):
        path = self.tmp / name
        path.write_text(content, encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
