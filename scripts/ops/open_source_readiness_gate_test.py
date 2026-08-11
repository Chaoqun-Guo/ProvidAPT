import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("open-source-readiness-gate.py")
SPEC = importlib.util.spec_from_file_location("open_source_readiness_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class OpenSourceReadinessGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-open-source-readiness-gate-test"
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
            release_gates=str(self.write_json("release-gates.json", {"gates": []})),
            operations_readiness_gate=str(self.write_json("operations.json", {"status": "pass"})),
            enterprise_readiness=str(self.write_json("enterprise.json", {"status": "pass"})),
            model_lifecycle_gate=str(self.tmp / "missing-model.json"),
            visual_regression_snapshots=str(self.tmp / "missing-visual.json"),
            onboarding_manifest=str(onboarding),
            plugin_gate=[],
            required_doc=[str(doc)],
            external_approval=str(doc),
        ))
        self.assertEqual(report["status"], "warn")
        self.assertEqual(report["sections"]["plugin_release_gates"]["status"], "warn")
        self.assertEqual(report["sections"]["model_lifecycle"]["status"], "warn")
        self.assertEqual(report["sections"]["visual_baselines"]["status"], "warn")
        self.assertIn("Open Source Readiness", subject.render_markdown(report))

    def test_build_report_blocks_on_missing_required_doc(self):
        approval = self.write_doc("approval.md", "approved\n")
        onboarding = self.write_json("onboarding.json", {"outputs": {"config": "a", "checklist": "b"}})
        plugin = self.write_json("plugin.json", {"status": "pass", "signature_present": True, "plugin": {"name": "demo"}})
        report = subject.build_report(Namespace(
            release_gates=str(self.write_json("release-gates.json", {"gates": [{"name": "ci", "status": "pass"}]})),
            operations_readiness_gate=str(self.write_json("operations.json", {"status": "pass"})),
            enterprise_readiness=str(self.write_json("enterprise.json", {"status": "pass"})),
            model_lifecycle_gate=str(self.write_json("model.json", {"status": "pass", "promotion_packet": {"decision": "approved_for_promotion", "model": {"name": "m", "version": "1"}, "evidence_count": 3, "next_actions": []}})),
            visual_regression_snapshots=str(self.write_json("visual.json", {"status": "pass", "coverage": {"covered_count": 8, "viewport_classes": ["mobile"], "complete_default_matrix": True}})),
            onboarding_manifest=str(onboarding),
            plugin_gate=[str(plugin)],
            required_doc=[str(self.tmp / "missing.md")],
            external_approval=str(approval),
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["open_source_documentation"]["missing_count"], 1)

    def test_build_report_accepts_local_milestone_evidence(self):
        approval = self.write_doc("approval.md", "approved\n")
        doc = self.write_doc("doc.md", "# Ready\n")
        onboarding = self.write_json("onboarding.json", {"outputs": {"config": "a", "checklist": "b"}})
        plugin = self.write_json("plugin.json", {"status": "pass", "signature_present": True, "plugin": {"name": "demo"}})
        release = self.write_json("release.json", {
            "full_commit": "abc",
            "version": "v1.2.3",
            "gates": [{"name": "github_actions", "status": "pass"}, {"name": "trivy_evidence", "status": "waived"}],
        })
        model = self.write_json("model.json", {
            "status": "pass",
            "promotion_packet": {
                "decision": "approved_for_promotion",
                "model": {"name": "graph-detector", "version": "1.0.0"},
                "evidence_count": 4,
                "next_actions": [],
            },
        })
        visual = self.write_json("visual.json", {
            "status": "pass",
            "coverage": {
                "covered_count": 8,
                "viewport_classes": ["mobile", "desktop_1366", "desktop_1080p", "ultrawide"],
                "complete_default_matrix": True,
                "missing_pages": [],
                "missing_default_viewports": [],
            },
        })
        report = subject.build_report(Namespace(
            release_gates=str(release),
            operations_readiness_gate=str(self.write_json("operations.json", {"status": "pass"})),
            enterprise_readiness=str(self.write_json("enterprise.json", {"status": "pass"})),
            model_lifecycle_gate=str(model),
            visual_regression_snapshots=str(visual),
            onboarding_manifest=str(onboarding),
            plugin_gate=[str(plugin)],
            required_doc=[str(doc)],
            external_approval=str(approval),
        ))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["sections"]["release_gate_status"]["commit"], "abc")
        self.assertTrue(report["sections"]["visual_baselines"]["complete_default_matrix"])
        self.assertEqual(report["sections"]["model_lifecycle"]["evidence_count"], 4)

if __name__ == "__main__":
    unittest.main()
