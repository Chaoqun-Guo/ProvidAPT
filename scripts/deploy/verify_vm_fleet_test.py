import importlib.util
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("verify-vm-fleet.py")
SPEC = importlib.util.spec_from_file_location("verify_vm_fleet", SCRIPT)
verify_vm = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(verify_vm)


class VerifyVMFleetTest(unittest.TestCase):
    def test_verify_passes_healthy_fleet_and_dashboard_markers(self):
        responses = {
            "/api/v1/status": {
                "status": "running",
                "health": "healthy",
                "diagnostics": {"version": "ProvidAPT [commit abc123]"},
            },
            "/api/v1/control/overview": {"total_agents": 3, "healthy_agents": 3},
            "/api/v1/control/fleet": {"agents": [
                {"agent_id": "a", "status": "HEALTHY", "last_report_age_seconds": 1, "version": "ProvidAPT abc123"},
                {"agent_id": "b", "status": "HEALTHY", "last_report_age_seconds": 2, "version": "ProvidAPT abc123"},
                {"agent_id": "c", "status": "HEALTHY", "last_report_age_seconds": 3, "version": "ProvidAPT abc123"},
            ]},
            "/api/v1/graph/export": {"elements": [{"data": {"id": "p:1"}}]},
            "/api/v1/control/alerts": {"alerts": [{"id": "alert-a"}]},
        }

        def fake_load_json(base_url, path, api_key=""):
            return responses[path]

        def fake_fetch(url, api_key="", timeout=10.0):
            return 200, b"graphSubsetForCluster exportClusterSubset openGraphTrace graph-cluster-actions", "text/html"

        args = Namespace(
            api_key="",
            min_agents=3,
            min_healthy=3,
            max_report_age_seconds=30,
            expected_commit="abc123",
            dashboard_markers=verify_vm.DEFAULT_MARKERS,
        )
        with mock.patch.object(verify_vm, "load_json_url", side_effect=fake_load_json), mock.patch.object(verify_vm, "fetch", side_effect=fake_fetch):
            report = verify_vm.verify("http://server", args)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["healthy_agents"], 3)
        self.assertEqual(len(report["agent_details"]), 3)
        self.assertEqual(report["agent_details"][0]["agent_id"], "a")
        self.assertIn("VM Fleet Verification", verify_vm.render_markdown(report))
        self.assertIn("| Agent | Hostname | Status | Age | Attachment | Enrollment | Alerts |", verify_vm.render_markdown(report))

    def test_verify_blocks_stale_or_missing_agents(self):
        responses = {
            "/api/v1/status": {"status": "running", "health": "healthy", "diagnostics": {"version": "ProvidAPT"}},
            "/api/v1/control/overview": {"total_agents": 1, "healthy_agents": 1},
            "/api/v1/control/fleet": {"agents": [
                {"agent_id": "a", "status": "HEALTHY", "last_report_age_seconds": 99, "version": "ProvidAPT old"},
            ]},
            "/api/v1/graph/export": {"elements": []},
            "/api/v1/control/alerts": {"alerts": []},
        }

        args = Namespace(
            api_key="",
            min_agents=3,
            min_healthy=3,
            max_report_age_seconds=30,
            expected_commit="abc123",
            dashboard_markers=["missingMarker"],
        )
        with mock.patch.object(verify_vm, "load_json_url", side_effect=lambda base, path, api_key="": responses[path]), mock.patch.object(verify_vm, "fetch", return_value=(200, b"dashboard", "text/html")):
            report = verify_vm.verify("http://server", args)
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any("expected at least" in item for item in report["failures"]))
        self.assertTrue(any("stale agents" in item for item in report["failures"]))

    def test_report_age_preserves_zero(self):
        self.assertEqual(verify_vm.report_age({"last_report_age_seconds": 0}), 0)
        self.assertEqual(verify_vm.report_age({"last_report_age_seconds": ""}, default=7), 7)


if __name__ == "__main__":
    unittest.main()
