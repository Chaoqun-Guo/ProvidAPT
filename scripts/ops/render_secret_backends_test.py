import base64
import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("render-secret-backends.py")
SPEC = importlib.util.spec_from_file_location("render_secret_backends", SCRIPT)
secrets = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(secrets)


class RenderSecretBackendsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-secret-backends-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_writes_redacted_backend_bundle(self):
        env_file = self.tmp / "providapt.secrets.env"
        env_file.write_text(
            "\ufeffPROVIDAPT_API_AUTH_KEYS=abcdef1234567890\n"
            "PROVIDAPT_DATABASE_DSN=postgres://providapt:supersecretpassword@example/db\n",
            encoding="utf-8",
        )
        out_dir = self.tmp / "out"
        manifest = secrets.write_bundle(Namespace(
            env_file=str(env_file),
            out_dir=str(out_dir),
            install_env_path="/etc/providapt/providapt.secrets.env",
            systemd_credential_dir="/etc/providapt/credentials",
            k8s_secret_name="providapt-runtime-secrets",
            k8s_namespace="providapt",
            vault_mount="secret",
            vault_path_prefix="providapt/runtime",
            include_values=False,
        ))
        self.assertEqual(manifest["schema"], secrets.SCHEMA)
        self.assertTrue((out_dir / "providapt-secrets.systemd.conf").exists())
        self.assertTrue((out_dir / "docker-compose.secrets.override.yml").exists())
        self.assertTrue((out_dir / "providapt-vault-policy.hcl").exists())
        self.assertTrue((out_dir / "providapt-vault-load.sh").exists())
        self.assertTrue((out_dir / "providapt-vault.config.yaml").exists())
        k8s = (out_dir / "providapt-runtime-secrets.yaml").read_text(encoding="utf-8")
        self.assertIn("kind: Secret", k8s)
        self.assertNotIn("supersecretpassword", k8s)
        vault_loader = (out_dir / "providapt-vault-load.sh").read_text(encoding="utf-8")
        self.assertIn("vault kv put secret/providapt/runtime/PROVIDAPT_API_AUTH_KEYS", vault_loader)
        self.assertNotIn("supersecretpassword", vault_loader)
        redacted = base64.b64encode("abcd<redacted>7890".encode()).decode()
        self.assertIn(redacted, k8s)
        loaded = json.loads((out_dir / "secret-backend-manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(loaded["redacted"])
        self.assertIn("vault", loaded["secret_backends"])


if __name__ == "__main__":
    unittest.main()
