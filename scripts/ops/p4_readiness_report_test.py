import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("p4-readiness-report.py")
SPEC = importlib.util.spec_from_file_location("p4_readiness_report", SCRIPT)
p4 = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(p4)


class P4ReadinessReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / "build" / "unit-tmp" / "p4-readiness"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir(parents=True)

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def write_doc(self, name, text="# Document\n"):
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_build_report_warns_without_plugin_evidence(self):
        doc = self.write_doc("handoff.md", "approved\n")
        onboarding = self.write_json("onboarding.json", {"mode": "standalone", "postgres": True, "outputs": {"config": "a", "checklist": "b"}})
        report = p4.build_report(Namespace(
            p3_readiness=str(self.write_json("p3.json", {"status": "pass"})),
            enterprise_readiness=str(self.write_json("enterprise.json", {"status": "pass"})),
            onboarding_manifest=str(onboarding),
            plugin_gate=[],
            required_doc=[str(doc)],
            external_approval=str(doc),
        ))
        self.assertEqual(report["status"], "warn")
        self.assertEqual(report["sections"]["plugin_release_gates"]["status"], "warn")
        self.assertIn("P4 Commercialization Readiness", p4.render_markdown(report))

    def test_build_report_blocks_on_missing_required_doc(self):
        approval = self.write_doc("approval.md", "approved\n")
        onboarding = self.write_json("onboarding.json", {"outputs": {"config": "a", "checklist": "b"}})
        plugin = self.write_json("plugin.json", {"status": "pass", "signature_present": True, "plugin": {"name": "demo"}})
        report = p4.build_report(Namespace(
            p3_readiness=str(self.write_json("p3.json", {"status": "pass"})),
            enterprise_readiness=str(self.write_json("enterprise.json", {"status": "pass"})),
            onboarding_manifest=str(onboarding),
            plugin_gate=[str(plugin)],
            required_doc=[str(self.tmp / "missing.md")],
            external_approval=str(approval),
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["commercial_documentation"]["missing_count"], 1)


if __name__ == "__main__":
    unittest.main()
