import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("commercialization-readiness-gate.py")
SPEC = importlib.util.spec_from_file_location("commercialization_readiness_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class CommercializationReadinessGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-commercialization-readiness-gate-test"
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
        report = subject.build_report(Namespace(
            operations_readiness_gate=str(self.write_json("operations.json", {"status": "pass"})),
            enterprise_readiness=str(self.write_json("enterprise.json", {"status": "pass"})),
            onboarding_manifest=str(onboarding),
            activation_server_gate=str(self.write_json("activation.json", {"status": "pass", "registry": {"entitlements": 1}, "audit": {"records": 2}, "live_probe": {"status": "skipped"}})),
            plugin_gate=[],
            required_doc=[str(doc)],
            external_approval=str(doc),
        ))
        self.assertEqual(report["status"], "warn")
        self.assertEqual(report["sections"]["plugin_release_gates"]["status"], "warn")
        self.assertIn("Commercialization Readiness", subject.render_markdown(report))

    def test_build_report_blocks_on_missing_required_doc(self):
        approval = self.write_doc("approval.md", "approved\n")
        onboarding = self.write_json("onboarding.json", {"outputs": {"config": "a", "checklist": "b"}})
        plugin = self.write_json("plugin.json", {"status": "pass", "signature_present": True, "plugin": {"name": "demo"}})
        report = subject.build_report(Namespace(
            operations_readiness_gate=str(self.write_json("operations.json", {"status": "pass"})),
            enterprise_readiness=str(self.write_json("enterprise.json", {"status": "pass"})),
            onboarding_manifest=str(onboarding),
            activation_server_gate=str(self.write_json("activation.json", {"status": "pass", "registry": {"entitlements": 1}, "audit": {"records": 2}, "live_probe": {"status": "skipped"}})),
            plugin_gate=[str(plugin)],
            required_doc=[str(self.tmp / "missing.md")],
            external_approval=str(approval),
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["commercial_documentation"]["missing_count"], 1)

    def test_build_report_blocks_without_activation_evidence(self):
        approval = self.write_doc("approval.md", "approved\n")
        onboarding = self.write_json("onboarding.json", {"outputs": {"config": "a", "checklist": "b"}})
        plugin = self.write_json("plugin.json", {"status": "pass", "signature_present": True, "plugin": {"name": "demo"}})
        report = subject.build_report(Namespace(
            operations_readiness_gate=str(self.write_json("operations.json", {"status": "pass"})),
            enterprise_readiness=str(self.write_json("enterprise.json", {"status": "pass"})),
            onboarding_manifest=str(onboarding),
            activation_server_gate=str(self.tmp / "missing-activation.json"),
            plugin_gate=[str(plugin)],
            required_doc=[str(approval)],
            external_approval=str(approval),
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["activation_server"]["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
