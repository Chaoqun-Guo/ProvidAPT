import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("production-readiness-gate.py")
SPEC = importlib.util.spec_from_file_location("production_readiness_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class P1ReadinessReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-production-readiness-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, data):
        path = self.tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_build_report_from_local_evidence(self):
        secret_manifest = self.write_json("secrets.json", {
            "variable_count": 2,
            "vault": {"mount": "secret", "path_prefix": "providapt/runtime"},
            "outputs": {
                "systemd_dropin": "systemd.conf",
                "docker_compose": "docker.yml",
                "kubernetes_secret": "secret.yaml",
                "vault_policy": "policy.hcl",
                "vault_loader": "load.sh",
                "vault_config": "vault.yaml",
            },
        })
        tls_manifest = self.write_json("tls.json", {
            "ca": {"cert": "ca.crt", "key": "ca.key", "fingerprint_sha256": "AA"},
            "server": {"cn": "cp", "san": "DNS:cp", "cert": "server.crt", "key": "server.key", "fingerprint_sha256": "BB"},
            "agents": [{"cn": "agent", "cert": "agent.crt", "key": "agent.key", "fingerprint_sha256": "CC"}],
        })
        postgres_report = self.write_json("postgres.json", {
            "backup": {"status": "pass", "bytes": 42},
            "restore": {"status": "skipped"},
            "schema_check": {"status": "skipped"},
        })
        report = subject.build_report(Namespace(
            secret_manifest=str(secret_manifest),
            tls_manifest=str(tls_manifest),
            postgres_report=str(postgres_report),
            server="",
            min_agents=3,
            min_healthy=3,
            max_report_age_seconds=60,
        ))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["sections"]["secret_backends"]["status"], "pass")
        self.assertEqual(report["sections"]["postgres_state"]["backup_bytes"], 42)

    def test_secret_backend_blocks_without_vault(self):
        section = subject.check_secret_backends({"variable_count": 1, "outputs": {"systemd_dropin": "x"}})
        self.assertEqual(section["status"], "blocked")
        self.assertTrue(section["failures"])


if __name__ == "__main__":
    unittest.main()
