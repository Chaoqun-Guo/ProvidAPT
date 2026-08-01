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
        config = self.write("providapt.yaml", self.production_config(rotation_auto=False))
        service = self.write("providapt.service", "PrivateTmp=true\nProtectHome=true\nRuntimeDirectory=providapt\nReadWritePaths=/var/log/providapt\nCapabilityBoundingSet=CAP_BPF\nNoNewPrivileges=false\n")
        env_file = self.write("providapt.env", 'PROVIDAPT_SKIP_PRIVILEGE_DROP=""\nPROVIDAPT_SKIP_SANITY_CHECKS=""\n')
        args = SimpleNamespace(config=str(config), service=str(service), env_file=str(env_file), rbac_audit="")

        report = gate.build_report(args)

        self.assertEqual(report["status"], "warn")
        self.assertEqual(report["sections"]["configuration"]["status"], "warn")
        self.assertTrue(any("rotation_auto" in item for item in report["sections"]["configuration"]["warnings"]))

    def test_blocks_missing_auth_and_tls(self):
        config = self.write("providapt.yaml", "encrypt: true\n")
        service = self.write("providapt.service", "")
        env_file = self.write("providapt.env", "")
        args = SimpleNamespace(config=str(config), service=str(service), env_file=str(env_file), rbac_audit="")

        report = gate.build_report(args)

        self.assertEqual(report["status"], "blocked")

    def test_blocks_wildcard_cors_and_env_secret_provider(self):
        config = self.write("providapt.yaml", self.production_config(cors="*", secrets_provider="env"))
        service = self.write("providapt.service", "PrivateTmp=true\nProtectHome=true\nRuntimeDirectory=providapt\nReadWritePaths=/var/log/providapt\nCapabilityBoundingSet=CAP_BPF\n")
        env_file = self.write("providapt.env", 'PROVIDAPT_SKIP_PRIVILEGE_DROP=""\nPROVIDAPT_SKIP_SANITY_CHECKS=""\n')
        args = SimpleNamespace(config=str(config), service=str(service), env_file=str(env_file), rbac_audit="")

        report = gate.build_report(args)

        self.assertEqual(report["status"], "blocked")
        failures = report["sections"]["configuration"]["failures"]
        self.assertTrue(any("cors_origins" in item for item in failures))
        self.assertTrue(any("secrets.provider" in item for item in failures))

    def write(self, name, content):
        path = self.tmp / name
        path.write_text(content, encoding="utf-8")
        return path

    def production_config(self, cors="https://soc.example.com", rotation_auto=True, secrets_provider="file"):
        return f"""api:
  auth_enabled: true
  auth_keys:
    - replace-with-key
  cors_origins:
    - {cors}
tls:
  enable: true
  cert_file: /etc/providapt/tls/server.crt
  key_file: /etc/providapt/tls/server.key
  ca_file: /etc/providapt/tls/ca.crt
  rotation_check: 24h
  rotation_renew_before: 720h
  rotation_auto: {str(rotation_auto).lower()}
telemetry:
  endpoint: https://cp-0.example.com:50051
  enable_tls: true
  cert_file: /etc/providapt/tls/agent.crt
  key_file: /etc/providapt/tls/agent.key
  ca_file: /etc/providapt/tls/ca.crt
  server_name: cp-0.example.com
policy:
  enabled: true
  endpoint: https://cp-0.example.com:18080
  api_key: env:PROVIDAPT_POLICY_API_KEY
  enable_tls: true
  ca_file: /etc/providapt/tls/ca.crt
storage:
  encrypt: true
compliance:
  require_approvals: true
support_bundle:
  redact_archives: true
secrets:
  provider: {secrets_provider}
  base_dir: /run/secrets/providapt
"""


if __name__ == "__main__":
    unittest.main()
