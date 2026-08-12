#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("open-source-local-closure.py")
spec = importlib.util.spec_from_file_location("open_source_local_closure", SCRIPT)
assert spec and spec.loader
subject = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = subject
spec.loader.exec_module(subject)


def args(**overrides: str) -> Namespace:
    defaults = {
        "server_url": "",
        "alert_ids": "",
        "release_tag": "",
        "signature": "",
        "model_closed_loop": "",
        "model_deploy_gate": "",
        "model_drift": "",
        "model_approval": "",
        "providapt_config": "",
        "rbac_audit": "",
        "policy_approval_gate": "",
        "audit_export": "",
        "role_review": "",
        "plugin_manifest": "",
        "plugin_signature": "",
        "plugin_gates": "",
    }
    defaults.update(overrides)
    return Namespace(**defaults)


class OpenSourceLocalClosureTest(unittest.TestCase):
    def test_missing_tools_and_inputs_block_rows(self) -> None:
        report = subject.build_report(args(), tool_resolver=lambda _tool: False)
        tasks = {row["id"]: row for row in report["tasks"]}

        self.assertEqual(report["status"], "blocked")
        self.assertIn("govulncheck", report["missing_tools"])
        self.assertIn("server_url", report["missing_inputs"])
        self.assertEqual(tasks["release-security-scans"]["status"], "blocked_missing_tool")
        self.assertEqual(tasks["visual-browser-baselines"]["status"], "blocked_missing_input")
        self.assertIn("Required local tools", tasks["release-security-scans"]["unable_reason"])
        self.assertIn("server_url", tasks["visual-browser-baselines"]["completion_requirement"])

    def test_ready_rows_when_required_context_is_supplied(self) -> None:
        supplied = args(
            server_url="http://127.0.0.1:18080",
            alert_ids="p:1 p:2",
            release_tag="v1.0.0",
            signature="dist/checksums.txt.sig",
            model_closed_loop="closed.json",
            model_deploy_gate="deploy.json",
            model_drift="drift.json",
            model_approval="approval.json",
            providapt_config="providapt.yaml",
            rbac_audit="rbac.json",
            policy_approval_gate="policy.json",
            audit_export="audit.ndjson",
            role_review="roles.json",
            plugin_manifest="plugin.json",
            plugin_signature="plugin.json.sig",
            plugin_gates="catalog.json",
        )
        report = subject.build_report(supplied, tool_resolver=lambda _tool: True)
        statuses = {row["id"]: row["status"] for row in report["tasks"]}

        self.assertNotIn("blocked_missing_input", set(statuses.values()))
        self.assertNotIn("blocked_missing_tool", set(statuses.values()))
        self.assertIn(statuses["onboarding-first-run-polish"], {"ready_to_run", "ready_to_rerun"})
        onboarding = next(row for row in report["tasks"] if row["id"] == "onboarding-first-run-polish")
        self.assertTrue(onboarding["unable_reason"])

    def test_markdown_lists_all_task_ids_and_blocker_sections(self) -> None:
        report = subject.build_report(args(), tool_resolver=lambda _tool: False)
        rendered = subject.render_markdown(report)

        for task in subject.TASKS:
            self.assertIn(task.task_id, rendered)
        self.assertIn("Missing Tools", rendered)
        self.assertIn("Missing Inputs", rendered)
        self.assertIn("Unable Reason", rendered)
        self.assertIn("Completion requirement", rendered)


if __name__ == "__main__":
    unittest.main()
