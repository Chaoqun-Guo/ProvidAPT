import importlib.util
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("trace-svg-stress.py")
SPEC = importlib.util.spec_from_file_location("trace_svg_stress", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class TraceSVGStressTest(unittest.TestCase):
    def test_svg_stats_count_nodes_edges_clusters(self):
        svg = '<svg width="1200" height="800"><g data-node-id="p:1"></g><path data-source="p:1"></path><g data-folded-count="3"></g></svg>'
        stats = subject.svg_stats(svg)
        self.assertEqual(stats["node_count"], 1)
        self.assertEqual(stats["edge_count"], 1)
        self.assertEqual(stats["cluster_count"], 1)
        self.assertEqual(stats["width"], 1200.0)
        self.assertTrue(stats["has_svg"])

    def test_build_report_blocks_slow_or_small_trace(self):
        def fake_request(server, alert_id, layout, api_key, timeout):
            return 200, '<svg width="10" height="10"></svg>', 2000.0

        original = subject.request_svg
        subject.request_svg = fake_request
        try:
            report = subject.build_report(Namespace(
                server="http://example.test",
                alert_id=["p:1"],
                layout=["tree"],
                api_key="",
                timeout_seconds=1,
                discover_limit=3,
                max_latency_ms=100,
                min_node_count=1,
            ))
        finally:
            subject.request_svg = original
        self.assertEqual(report["status"], "blocked")
        text = "\n".join(report["failures"])
        self.assertIn("latency", text)
        self.assertIn("node count", text)

    def test_discovers_alert_ids_when_omitted(self):
        def fake_discover(server, api_key, timeout, limit):
            return ["a:1", "a:2"]

        def fake_request(server, alert_id, layout, api_key, timeout):
            return 200, '<svg width="100" height="100"><g data-node-id="p:1"></g></svg>', 10.0

        original_discover = subject.discover_alert_ids
        original_request = subject.request_svg
        subject.discover_alert_ids = fake_discover
        subject.request_svg = fake_request
        try:
            report = subject.build_report(Namespace(
                server="http://example.test",
                alert_id=[],
                layout=["tree"],
                api_key="",
                timeout_seconds=1,
                discover_limit=3,
                max_latency_ms=100,
                min_node_count=1,
            ))
        finally:
            subject.discover_alert_ids = original_discover
            subject.request_svg = original_request
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["alert_source"], "discovered")
        self.assertEqual(report["alert_ids"], ["a:1", "a:2"])

    def test_blocks_when_no_alert_ids_are_available(self):
        original_discover = subject.discover_alert_ids
        subject.discover_alert_ids = lambda server, api_key, timeout, limit: []
        try:
            report = subject.build_report(Namespace(
                server="http://example.test",
                alert_id=[],
                layout=["tree"],
                api_key="",
                timeout_seconds=1,
                discover_limit=3,
                max_latency_ms=100,
                min_node_count=1,
            ))
        finally:
            subject.discover_alert_ids = original_discover
        self.assertEqual(report["status"], "blocked")
        self.assertIn("no alert IDs supplied or discovered", "\n".join(report["failures"]))


if __name__ == "__main__":
    unittest.main()
