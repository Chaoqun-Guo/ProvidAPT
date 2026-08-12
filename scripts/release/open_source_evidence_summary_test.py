import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("open-source-evidence-summary.py")
SPEC = importlib.util.spec_from_file_location("open_source_evidence_summary", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class OpenSourceEvidenceSummaryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-open-source-evidence-summary-test"
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
            "open_source_milestone": missing,
            "open_source_readiness_backlog": missing,
            "visual_regression_gate": missing,
            "trace_svg_stress": missing,
            "onboarding_manifest": missing,
            "allow_missing": False,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_allow_missing_records_warnings(self):
        report = subject.build_report(self.args(allow_missing=True))
        self.assertEqual(report["status"], "warn")
        self.assertEqual(report["blocker_count"], 0)
        self.assertEqual(report["warning_count"], 5)
        rendered = subject.render_markdown(report)
        self.assertIn("Open Source Evidence Summary", rendered)
        self.assertIn("evidence is missing", rendered)

    def test_summarizes_release_blockers(self):
        milestone = self.write_json("milestone.json", {
            "status": "blocked",
            "evidence": [
                {"name": "visual_regression_snapshots", "status": "warn"},
                {"name": "trace_svg_stress", "status": "blocked"},
            ],
        })
        backlog = self.write_json("backlog.json", {
            "source_status": "blocked",
            "task_count": 2,
            "checklist_summary": {
                "release_blocking_count": 1,
                "blocked_sections": ["visual_baselines"],
                "warning_sections": ["model_lifecycle"],
            },
            "tasks": [{"id": "visual_baselines-1"}, {"id": "model_lifecycle-1"}],
        })
        visual = self.write_json("visual.json", {
            "status": "blocked",
            "visual_evidence_summary": {
                "required_matrix": {
                    "missing_count": 2,
                    "missing_by_page": {"dashboard": ["390x844"]},
                },
                "dom_assertions": {"failed": 1, "missing": 0},
                "baseline": {"status": "changed", "changed": 1},
            },
            "failures": ["dashboard 390x844 DOM assertions failed"],
        })
        trace = self.write_json("trace.json", {
            "status": "blocked",
            "results": [
                {"layout": "tree", "http_status": 200, "latency_ms": 20},
                {"layout": "compact", "http_status": 500, "latency_ms": 0},
            ],
            "failures": ["compact failed"],
        })
        onboarding = self.write_json("onboarding.json", {
            "status": "blocked",
            "check_summary": {"pass": 1, "warn": 1, "fail": 1, "unknown": 1, "skipped": 0, "total": 4},
            "action_summary": {
                "action_count": 3,
                "blocked_checks": ["api"],
                "warning_checks": ["tls"],
                "unknown_checks": ["ssh"],
            },
        })
        report = subject.build_report(self.args(
            open_source_milestone=milestone,
            open_source_readiness_backlog=backlog,
            visual_regression_gate=visual,
            trace_svg_stress=trace,
            onboarding_manifest=onboarding,
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertGreaterEqual(report["blocker_count"], 5)
        messages = "\n".join(item["message"] for item in report["blockers"])
        self.assertIn("milestone evidence blocked: trace_svg_stress", messages)
        self.assertIn("release-blocking section: visual_baselines", messages)
        self.assertIn("visual matrix missing screenshots: 2", messages)
        self.assertIn("trace stress failed layout: compact", messages)
        self.assertIn("onboarding blocked check: api", messages)
        rendered = subject.render_markdown(report)
        self.assertIn("## Blockers", rendered)
        self.assertIn("## Evidence Details", rendered)
        self.assertIn("visual_baselines", rendered)


if __name__ == "__main__":
    unittest.main()
