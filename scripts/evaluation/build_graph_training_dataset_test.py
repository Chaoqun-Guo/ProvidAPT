from __future__ import annotations

import argparse
import json
import unittest
from pathlib import Path

from scripts.evaluation import build_graph_training_dataset as subject


class BuildGraphTrainingDatasetTest(unittest.TestCase):
    def test_builds_labeled_graphs_from_events_and_truth(self) -> None:
        root = Path.cwd() / "build" / "unit-tmp" / "graph-dataset"
        root.mkdir(parents=True, exist_ok=True)
        events = root / "events.ndjson"
        truth = root / "ground_truth.jsonl"
        feedback = root / "alert-feedback.ndjson"
        event_rows = [
            {"Type": 2, "TimestampNS": 1_000_000_000, "PID": 10, "PPID": 1, "UID": 0, "Comm": "bash", "Pathname": "/bin/bash"},
            {"type": "net_connect", "timestamp_ns": 2_000_000_000, "process": {"pid": 11, "uid": 0, "comm": "curl"}, "payload": {"daddr": "127.0.0.1", "dport": 1}, "enrich": {"cmdline": "curl http://127.0.0.1:1/beacon", "cmdline_source": "procfs", "cwd": "/tmp", "exe_path": "/usr/bin/curl"}},
            {"Type": 1, "TimestampNS": 3_000_000_000, "PID": 12, "UID": 1000, "Comm": "date"},
        ]
        truth_rows = [
            {
                "run_id": "run-1",
                "timestamp": "1970-01-01T00:00:02Z",
                "step_id": "fc-14",
                "step_name": "Beacon over HTTP",
                "tactic_id": "TA0011",
                "technique_id": "T1071.001",
                "command": "curl http://127.0.0.1:1/beacon",
                "actor": "curl",
                "object": "127.0.0.1:1",
                "malicious": True,
            }
        ]
        events.write_text("\n".join(json.dumps(row) for row in event_rows) + "\n", encoding="utf-8")
        truth.write_text("\n".join(json.dumps(row) for row in truth_rows) + "\n", encoding="utf-8")
        feedback.write_text(
            json.dumps({
                "schema": "providapt.alert_feedback.v1",
                "alert_id": "alert-1",
                "action": "annotate",
                "classification": "true_positive",
                "created_at": "2026-07-28T00:00:00Z",
            })
            + "\n",
            encoding="utf-8",
        )
        args = argparse.Namespace(
            window_seconds=5.0,
            negative_ratio=1.0,
            normal_window_events=2,
            split_seed="test",
            dataset_version="test",
            alert_feedback=[str(feedback)],
        )

        graphs, metadata = subject.build_dataset([events], [truth], args)

        self.assertGreaterEqual(len(graphs), 2)
        self.assertEqual(metadata["manifest"]["ground_truth_count"], 1)
        self.assertEqual(metadata["manifest"]["label_summary"]["malicious"], 1)
        self.assertIn("feature_schema_sha256", metadata["manifest"])
        self.assertEqual(metadata["manifest"]["quality"]["truth_matched_count"], 1)
        self.assertEqual(metadata["manifest"]["quality"]["truth_fallback_count"], 0)
        self.assertEqual(metadata["manifest"]["alert_feedback"]["feedback_entry_count"], 1)
        self.assertEqual(metadata["manifest"]["alert_feedback"]["feedback_by_classification"]["true_positive"], 1)
        self.assertGreater(metadata["manifest"]["quality"]["cmdline_present_percent"], 0)
        malicious = [graph for graph in graphs if graph["label"] == 1][0]
        self.assertIn("TA0011", malicious["tactics"])
        self.assertTrue(any(node["type"] == "network" for node in malicious["nodes"]))

    def test_legacy_type_two_is_process_exec(self) -> None:
        self.assertEqual(subject.normalize_type({"Type": 2}), "proc_exec")
        self.assertEqual(subject.edge_kind(subject.normalize_type({"Type": 2}), "", ""), "exec")


if __name__ == "__main__":
    unittest.main()
