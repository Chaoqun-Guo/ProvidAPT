import hmac
import hashlib
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_upgrade_artifact as builder


class BuildUpgradeArtifactTest(unittest.TestCase):
    def test_writes_manifest_checksum_and_hmac_signature(self):
        root = Path.cwd() / ".tmp-tests" / "upgrade-artifact" / uuid.uuid4().hex
        root.mkdir(parents=True, exist_ok=True)
        artifact = root / "providapt.tar.gz"
        artifact.write_bytes(b"upgrade-package")
        out_dir = root / "out"
        args = SimpleNamespace(
            artifact=str(artifact),
            version="v9.9.9",
            base_url="http://auth.example/artifacts/",
            out_dir=str(out_dir),
            minimum_version="v1.0.0",
            release_notes="https://example/release",
            published_at="2026-07-29T00:00:00+00:00",
            signing_key="secret",
        )

        manifest = builder.write_outputs(args)

        copied = out_dir / artifact.name
        checksum = hashlib.sha256(copied.read_bytes()).hexdigest()
        expected_sig = hmac.new(b"secret", checksum.encode("utf-8"), hashlib.sha256).hexdigest()
        self.assertEqual(manifest["version"], "v9.9.9")
        self.assertEqual(manifest["expected_sha256"], checksum)
        self.assertEqual((out_dir / "providapt.tar.gz.sig").read_text(encoding="utf-8").strip(), expected_sig)
        self.assertTrue((out_dir / "latest.json").exists())
        self.assertTrue((out_dir / "upgrade-artifact.md").exists())


if __name__ == "__main__":
    unittest.main()
