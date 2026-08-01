import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("configure-vm-endpoints.py")
SPEC = importlib.util.spec_from_file_location("configure_vm_endpoints", SCRIPT)
configure_vm = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(configure_vm)


class ConfigureVMEndpointsTest(unittest.TestCase):
    def test_update_endpoints_preserves_other_config(self):
        original = """api:
  rest: ":8080"
telemetry:
  endpoint: "old-control.example:50051"
  interval: "5s"
policy:
  enabled: true
  endpoint: "http://old-control.example:18080"
"""
        rendered, changed = configure_vm.update_endpoints(
            original,
            "vm-ubuntu-master.ts.net.example:50051",
            "http://vm-ubuntu-master.ts.net.example:18080",
        )
        self.assertIn('endpoint: "vm-ubuntu-master.ts.net.example:50051"', rendered)
        self.assertIn('endpoint: "http://vm-ubuntu-master.ts.net.example:18080"', rendered)
        self.assertIn('rest: ":8080"', rendered)
        self.assertEqual(changed, {"telemetry": True, "policy": True})
        self.assertEqual(configure_vm.legacy_hits(rendered, ["192.168.150."]), [])

    def test_missing_endpoint_fails(self):
        with self.assertRaisesRegex(ValueError, "missing endpoint"):
            configure_vm.update_endpoints("telemetry:\n  interval: 5s\n", "host:50051", "http://host:18080")

    def test_in_place_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "providapt.toml"
            path.write_text('telemetry:\n  endpoint: "old:50051"\npolicy:\n  endpoint: "http://old:18080"\n', encoding="utf-8")
            rendered, _ = configure_vm.update_endpoints(
                path.read_text(encoding="utf-8"),
                "master.example:50051",
                "http://master.example:18080",
            )
            path.write_text(rendered, encoding="utf-8")
            self.assertIn("master.example", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
