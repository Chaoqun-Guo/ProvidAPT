import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("plugin-marketplace-lite.py")
SPEC = importlib.util.spec_from_file_location("plugin_marketplace_lite", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class PluginMarketplaceLiteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-plugin-marketplace-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_builds_open_source_plugin_directory(self):
        catalog = self.tmp / "catalog.json"
        catalog.write_text(json.dumps({
            "status": "pass",
            "distribution_catalog": [{
                "name": "official-sample-detector",
                "version": "1.0.0",
                "artifact": "official-sample-detector-1.0.0.bundle",
                "signed": True,
                "signature_hash_matches": True,
                "permissions": ["rules:read", "alerts:write"],
                "providapt_min_version": "1.2.0",
                "rollback_drill_status": "pass",
            }],
        }), encoding="utf-8")
        report = subject.build_marketplace(Namespace(
            plugin_catalog=str(catalog),
            out_json=str(self.tmp / "marketplace.json"),
            out_md=str(self.tmp / "marketplace.md"),
        ))
        self.assertEqual(report["schema"], subject.SCHEMA)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["plugin_count"], 1)
        entry = report["plugins"][0]
        self.assertEqual(entry["manifest"], "official-sample-detector:1.0.0")
        self.assertEqual(entry["signature_status"], "verified")
        self.assertEqual(entry["rollback"], "pass")
        rendered = subject.render_markdown(report)
        self.assertIn("Plugin Marketplace Lite", rendered)
        self.assertIn("official-sample-detector", rendered)


if __name__ == "__main__":
    unittest.main()
