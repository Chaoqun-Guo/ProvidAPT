import importlib.util
import json
import shutil
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("open-source-development-backlog.py")
SPEC = importlib.util.spec_from_file_location("open_source_development_backlog", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class OpenSourceDevelopmentBacklogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-open-source-development-backlog-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def test_build_report_groups_tasks(self):
        report = subject.build_report()
        self.assertEqual(report["schema"], subject.SCHEMA)
        self.assertGreaterEqual(report["task_count"], 8)
        self.assertIn("release", report["by_phase"])
        self.assertIn("blocked_external", report["by_status"])

    def test_local_only_filters_external_blockers(self):
        report = subject.build_report(local_only=True)
        self.assertTrue(report["tasks"])
        self.assertTrue(all(task["local"] for task in report["tasks"]))
        self.assertNotIn("release-owner-approval", {task["id"] for task in report["tasks"]})

    def test_phase_filter_and_markdown(self):
        report = subject.build_report(phase="frontend")
        self.assertEqual({task["phase"] for task in report["tasks"]}, {"frontend"})
        out = subject.render_markdown(report)
        self.assertIn("Open Source Development Backlog", out)
        self.assertIn("visual-browser-baselines", out)

    def test_evidence_paths_update_task_statuses(self):
        visual = self.write_json("visual.json", {"status": "pass"})
        model = self.write_json("model.json", {"status": "warn"})
        plugin = self.write_json("plugin.json", {"status": "blocked"})
        onboarding = self.write_json("onboarding.json", {"schema": "providapt.onboarding_bundle.v1", "outputs": {"config": "a", "checklist": "b"}})
        report = subject.build_report(local_only=True, evidence_paths={
            "visual_regression_gate": visual,
            "model_lifecycle_gate": model,
            "plugin_catalog_gate": plugin,
            "onboarding_manifest": onboarding,
        })
        tasks = {task["id"]: task for task in report["tasks"]}
        self.assertEqual(tasks["visual-browser-baselines"]["status"], "done")
        self.assertEqual(tasks["model-lifecycle-baseline"]["status"], "needs_review")
        self.assertEqual(tasks["plugin-distribution"]["status"], "needs_fix")
        self.assertEqual(tasks["onboarding-first-run-polish"]["status"], "done")
        self.assertGreaterEqual(report["by_evidence_status"]["pass"], 1)
        self.assertEqual(report["by_evidence_status"]["warn"], 1)
        planning = report["planning_summary"]
        self.assertGreaterEqual(planning["next_local_count"], 1)
        self.assertEqual(planning["next_local_tasks"][0], "plugin-distribution")
        self.assertIn("model-lifecycle-baseline", planning["next_local_tasks"])
        self.assertIn("plugin-distribution", planning["by_evidence_key"]["plugin_catalog_gate"])
        self.assertNotIn("visual-browser-baselines", planning["next_local_tasks"])
        self.assertNotIn("onboarding-first-run-polish", planning["next_local_tasks"])
        plugin_detail = next(item for item in planning["next_local_details"] if item["id"] == "plugin-distribution")
        self.assertEqual(plugin_detail["evidence_status"], "blocked")
        self.assertEqual(plugin_detail["blocker_type"], "owner_evidence")
        self.assertIn("plugin_catalog_gate", plugin_detail["reason"])
        rendered = subject.render_markdown(report)
        self.assertIn("Planning Summary", rendered)
        self.assertIn("Next Local Task", rendered)
        self.assertIn("Blocker", rendered)
        self.assertIn("visual_regression_gate:pass", rendered)

    def test_multi_evidence_tasks_are_aggregated(self):
        pass_gate = self.write_json("pass.json", {"status": "pass"})
        warn_gate = self.write_json("warn.json", {"status": "warn"})
        blocked_gate = self.write_json("blocked.json", {"status": "blocked"})
        report = subject.build_report(evidence_paths={
            "release_evidence_consistency_gate": pass_gate,
            "artifact_signing_gate": pass_gate,
            "operator_release_gate": pass_gate,
            "capture_enrichment_gate": pass_gate,
            "soak_readiness": warn_gate,
            "siem_verify": pass_gate,
            "operator_env_certification_gate": blocked_gate,
            "rbac_audit": pass_gate,
            "policy_approval_gate": pass_gate,
        })
        tasks = {task["id"]: task for task in report["tasks"]}
        self.assertEqual(tasks["release-final-artifacts"]["status"], "done")
        self.assertEqual(tasks["capture-field-evidence-refresh"]["status"], "done")
        self.assertEqual(tasks["soak-accelerated"]["status"], "needs_review")
        self.assertEqual(tasks["siem-soar-certification"]["status"], "needs_fix")
        self.assertEqual(tasks["rbac-audit-hardening"]["status"], "needs_fix")
        self.assertEqual(tasks["release-final-artifacts"]["evidence_status"], "pass")
        planning = report["planning_summary"]
        self.assertIn("soak-accelerated", planning["next_local_tasks"])
        self.assertIn("siem-soar-certification", planning["external_blockers"])
        self.assertIn("rbac-audit-hardening", planning["by_evidence_key"]["operator_env_certification_gate"])
        soak_detail = subject.planning_task_detail(tasks["soak-accelerated"])
        owner_detail = subject.planning_task_detail(tasks["release-final-artifacts"])
        self.assertEqual(soak_detail["blocker_type"], "runtime_evidence")
        self.assertEqual(owner_detail["blocker_type"], "owner_evidence")
        rendered = subject.render_markdown(report)
        self.assertIn("artifact_signing_gate:pass", rendered)
        self.assertIn("operator_env_certification_gate:blocked", rendered)

    def test_release_security_scans_use_scanner_subgates(self):
        release_gates = self.write_json("release-gates.json", {
            "gates": [
                {"name": "github_actions", "status": "skipped"},
                {"name": "govulncheck_evidence", "status": "pass"},
                {"name": "grype_evidence", "status": "pass"},
                {"name": "trivy_evidence", "status": "pass"},
                {"name": "external_approvals", "status": "blocked"},
            ],
        })
        report = subject.build_report(evidence_paths={"release_gates": release_gates})
        tasks = {task["id"]: task for task in report["tasks"]}
        self.assertEqual(tasks["release-security-scans"]["status"], "done")
        self.assertEqual(tasks["release-security-scans"]["evidence_status"], "pass")
        self.assertEqual(tasks["release-owner-approval"]["status"], "blocked_external")
        self.assertNotIn("release-security-scans", report["planning_summary"]["next_local_tasks"])


if __name__ == "__main__":
    unittest.main()
