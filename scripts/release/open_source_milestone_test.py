import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("open-source-milestone.py")
SPEC = importlib.util.spec_from_file_location("open_source_milestone", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class OpenSourceMilestoneTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-open-source-milestone-test"
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

    def args(self, **overrides):
        missing = str(self.tmp / "missing.json")
        values = {
            "open_source_readiness_gate": missing,
            "open_source_readiness_backlog": missing,
            "open_source_development_backlog": missing,
            "release_gates": missing,
            "release_evidence_consistency_gate": missing,
            "model_lifecycle_gate": missing,
            "visual_regression_snapshots": missing,
            "trace_svg_stress": missing,
            "onboarding_manifest": missing,
            "allow_missing": False,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_allow_missing_turns_missing_inputs_into_warning(self):
        report = subject.build_report(self.args(allow_missing=True))
        self.assertEqual(report["status"], "warn")
        self.assertFalse(report["evidence"][0]["present"])
        self.assertIn("Open Source Milestone", subject.render_markdown(report))

    def test_task_backlog_without_status_is_usable_evidence(self):
        backlog = {"schema": "providapt.open_source_development_backlog.v1", "task_count": 8}
        self.assertEqual(subject.status_value(backlog, allow_missing=False), "pass")

    def test_milestone_includes_model_and_visual_details(self):
        readiness = self.write_json("readiness.json", {
            "schema": "providapt.open_source_readiness.v1",
            "status": "pass",
            "sections": {"docs": {"status": "pass"}},
        })
        readiness_backlog = self.write_json("readiness-backlog.json", {
            "schema": "providapt.release_blocker_backlog.v1",
            "source_status": "pass",
            "task_count": 0,
        })
        development_backlog = self.write_json("development-backlog.json", {
            "schema": "providapt.open_source_development_backlog.v1",
            "status": "pass",
            "task_count": 4,
            "filters": {"evidence_aware": True},
            "by_status": {"done": 1, "needs_fix": 1, "needs_review": 1, "blocked_external": 1},
            "by_evidence_status": {"pass": 1, "blocked": 1, "warn": 1, "missing": 1},
            "planning_summary": {
                "remaining_count": 3,
                "next_local_count": 2,
                "next_local_tasks": ["plugin-distribution", "model-lifecycle-baseline"],
                "external_blocker_count": 1,
                "external_blockers": ["release-ci-evidence"],
                "by_evidence_key": {
                    "plugin_catalog_gate": ["plugin-distribution"],
                    "github_actions_evidence": ["release-ci-evidence"],
                },
            },
            "tasks": [
                {"id": "visual-browser-baselines", "status": "done", "evidence_status": "pass"},
                {"id": "plugin-distribution", "status": "needs_fix", "evidence_status": "blocked"},
                {"id": "model-lifecycle-baseline", "status": "needs_review", "evidence_status": "warn"},
                {"id": "release-ci-evidence", "status": "blocked_external", "evidence_status": "missing"},
            ],
        })
        release = self.write_json("release.json", {"status": "pass", "gates": []})
        release_evidence = self.write_json("release-evidence.json", {"status": "pass"})
        model = self.write_json("model.json", {
            "status": "pass",
            "promotion_packet": {
                "readiness_summary": {
                    "decision": "approved_for_promotion",
                    "model": {"name": "graph-detector", "version": "1.0.0"},
                    "drift_status": "stable",
                    "baseline_days": 14,
                    "feedback": {
                        "records": 40,
                        "reviewed": 22,
                        "labels": {"false_positive": 8, "true_positive": 10},
                    },
                    "blocker_count": 0,
                    "warning_count": 0,
                    "evidence": {"present": ["closed_loop", "deploy_gate"], "missing": ["approval"]},
                }
            },
        })
        visual = self.write_json("visual.json", {
            "status": "warn",
            "coverage": {
                "complete_default_matrix": True,
                "covered_count": 8,
                "screenshot_count": 8,
                "viewport_classes": ["desktop_1366", "desktop_1080p", "mobile", "ultrawide"],
            },
            "comparison_summary": {
                "status": "changed",
                "counts": {"changed": 1, "unchanged": 7},
            },
            "screenshots": [
                {"page": "dashboard", "status": "captured", "dom_assertions": {"status": "pass"}},
                {"page": "trace-viewer", "status": "captured", "dom_assertions": {"status": "fail"}},
            ],
        })
        trace = self.write_json("trace.json", {
            "schema": "providapt.trace_svg_stress.v1",
            "status": "blocked",
            "alert_source": "provided",
            "alert_ids": ["p:1"],
            "layouts": ["tree", "compact"],
            "thresholds": {"max_latency_ms": 1500, "min_node_count": 1},
            "results": [
                {
                    "alert_id": "p:1",
                    "layout": "tree",
                    "http_status": 200,
                    "latency_ms": 120.5,
                    "node_count": 8,
                    "edge_count": 7,
                },
                {
                    "alert_id": "p:1",
                    "layout": "compact",
                    "http_status": 500,
                    "latency_ms": 0,
                    "error": "layout failed",
                },
            ],
            "failures": ["p:1/compact: HTTP 500"],
        })
        onboarding = self.write_json("onboarding.json", {
            "schema": "providapt.onboarding_bundle.v1",
            "status": "blocked",
            "mode": "standalone",
            "postgres": False,
            "check_summary": {"pass": 1, "warn": 1, "fail": 1, "unknown": 2, "skipped": 0, "total": 5},
            "action_summary": {
                "action_count": 4,
                "blocked_checks": ["api"],
                "warning_checks": ["tls"],
                "unknown_checks": ["ssh", "dashboard"],
                "skipped_checks": [],
                "by_status": {"fail": ["api"], "warn": ["tls"], "unknown": ["dashboard", "ssh"]},
                "by_severity": {"required": ["api", "dashboard", "ssh", "tls"]},
                "top_actions": [
                    {
                        "check": "api",
                        "status": "fail",
                        "command": "curl -fsS http://127.0.0.1:18080/api/v1/status",
                        "next_step": "Start providaptd.",
                    }
                ],
            },
            "outputs": {"config": "a", "checklist": "b", "report": "c"},
        })
        report = subject.build_report(self.args(
            open_source_readiness_gate=readiness,
            open_source_readiness_backlog=readiness_backlog,
            open_source_development_backlog=development_backlog,
            release_gates=release,
            release_evidence_consistency_gate=release_evidence,
            model_lifecycle_gate=model,
            visual_regression_snapshots=visual,
            trace_svg_stress=trace,
            onboarding_manifest=onboarding,
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["evidence"][0]["section_count"], 1)
        self.assertEqual(report["evidence"][1]["task_count"], 0)
        backlog_row = next(item for item in report["evidence"] if item["name"] == "open_source_development_backlog")
        self.assertEqual(backlog_row["development_backlog"]["remaining_count"], 3)
        self.assertIn("plugin-distribution", backlog_row["development_backlog"]["needs_fix"])
        self.assertIn("release-ci-evidence", backlog_row["development_backlog"]["missing_evidence"])
        planning = backlog_row["development_backlog"]["planning_summary"]
        self.assertEqual(planning["next_local_count"], 2)
        self.assertIn("plugin-distribution", planning["next_local_tasks"])
        self.assertIn("release-ci-evidence", planning["external_blockers"])
        self.assertIn("plugin-distribution", planning["by_evidence_key"]["plugin_catalog_gate"])
        model_row = next(item for item in report["evidence"] if item["name"] == "model_lifecycle")
        self.assertEqual(model_row["model_lifecycle"]["promotion_decision"], "approved_for_promotion")
        self.assertEqual(model_row["model_lifecycle"]["feedback_labels"]["true_positive"], 10)
        visual_row = next(item for item in report["evidence"] if item["name"] == "visual_regression_snapshots")
        self.assertEqual(visual_row["visual_regression"]["changed_count"], 1)
        self.assertTrue(visual_row["visual_regression"]["complete_default_matrix"])
        self.assertEqual(visual_row["visual_regression"]["dom_assertions"]["failed"], 1)
        trace_row = next(item for item in report["evidence"] if item["name"] == "trace_svg_stress")
        self.assertEqual(trace_row["trace_svg_stress"]["result_count"], 2)
        self.assertEqual(trace_row["trace_svg_stress"]["failure_count"], 1)
        self.assertEqual(trace_row["trace_svg_stress"]["failed_layouts"], ["compact"])
        self.assertEqual(trace_row["trace_svg_stress"]["max_latency_ms"], 120.5)
        onboarding_row = next(item for item in report["evidence"] if item["name"] == "onboarding_manifest")
        self.assertEqual(onboarding_row["onboarding"]["action_count"], 4)
        self.assertEqual(onboarding_row["onboarding"]["blocked_checks"], ["api"])
        self.assertIn("dashboard", onboarding_row["onboarding"]["unknown_checks"])
        rendered = subject.render_markdown(report)
        self.assertIn("model=graph-detector:1.0.0", rendered)
        self.assertIn("decision=approved_for_promotion", rendered)
        self.assertIn("missing_evidence=approval", rendered)
        self.assertIn("coverage=8/8", rendered)
        self.assertIn("baseline=changed", rendered)
        self.assertIn("dom_failed=1/2", rendered)
        self.assertIn("trace_results=2", rendered)
        self.assertIn("Trace SVG Stress", rendered)
        self.assertIn("compact", rendered)
        self.assertIn("onboarding_actions=4", rendered)
        self.assertIn("Onboarding", rendered)
        self.assertIn("Blocked Checks", rendered)
        self.assertIn("Start providaptd.", rendered)
        self.assertIn("Development Backlog", rendered)
        self.assertIn("next_local=plugin-distribution,model-lifecycle-baseline", rendered)
        self.assertIn("External blockers", rendered)
        self.assertIn("plugin_catalog_gate", rendered)
        self.assertIn("plugin-distribution", rendered)
        self.assertIn("release-ci-evidence", rendered)


if __name__ == "__main__":
    unittest.main()
