import importlib.util
import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).with_name("install-delivery-check.py")
SPEC = importlib.util.spec_from_file_location("install_delivery_check", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(checker)


class InstallDeliveryCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-install-delivery-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_passes_with_expected_assets(self):
        root = self.tmp / "root"
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        for name in checker.REQUIRED_BINS:
            (bin_dir / name).write_text("bin\n", encoding="utf-8")
        for doc in checker.REQUIRED_DOCS:
            path = root / doc
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("doc\n", encoding="utf-8")
        config = self.write("providapt.yaml", "enable: true\nencrypt: true\n")
        service = self.write("providapt.service", "ExecStart=x\nEnvironmentFile=x\nRestart=on-failure\nRuntimeDirectory=providapt\nPrivateTmp=true\nProtectHome=true\nReadWritePaths=/var/log/providapt\n")
        env_file = self.write("providapt.env", 'PROVIDAPT_SKIP_PRIVILEGE_DROP=""\n')
        args = SimpleNamespace(root=str(root), bin_dir=str(bin_dir), config=str(config), service=str(service), env_file=str(env_file), strict_binaries=True)

        report = checker.build_report(args)

        self.assertEqual(report["status"], "pass")

    def test_blocks_missing_strict_binary(self):
        root = self.tmp / "root"
        root.mkdir()
        args = SimpleNamespace(root=str(root), bin_dir=str(self.tmp / "missing"), config=str(self.tmp / "missing.yaml"), service=str(self.tmp / "missing.service"), env_file=str(self.tmp / "missing.env"), strict_binaries=True)

        report = checker.build_report(args)

        self.assertEqual(report["status"], "blocked")

    def write(self, name, content):
        path = self.tmp / name
        path.write_text(content, encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
