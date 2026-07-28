import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("p2-readiness-report.py")
SPEC = importlib.util.spec_from_file_location("p2_readiness_report", SCRIPT)
p2 = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(p2)


class P2ReadinessReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / "build" / "unit-tmp" / "p2-readiness"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir(parents=True)

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, data):
        path = self.tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_build_report_passes_with_quality_and_metrics(self):
        manifest = self.write_json("manifest.json", {
            "record_count": 200,
            "event_source_count": 2000,
            "label_summary": {"malicious": 50, "benign": 150},
            "quality": {
                "truth_match_rate_percent": 100.0,
                "cmdline_present_percent": 60.0,
                "path_present_percent": 70.0,
            },
        })
        metrics = self.write_json("metrics.json", {
            "architecture": "gat",
            "device": "cpu",
            "dataset_records": 200,
            "test_metrics": {
                "support": 50,
                "precision_percent": 90.0,
                "recall_percent": 88.0,
                "f1_percent": 89.0,
                "roc_auc_percent": 95.0,
                "pr_auc_percent": 94.0,
                "confusion": {"tp": 22, "fp": 2, "tn": 23, "fn": 3},
            },
        })
        report = p2.build_report(Namespace(
            dataset_manifest=str(manifest),
            metrics=str(metrics),
            model_gate="",
            events=[],
            normal_events=[],
            ground_truth=[],
            window_seconds=300,
            min_graphs=100,
            min_source_events=1000,
            min_malicious_graphs=10,
            min_benign_graphs=10,
            min_truth_match_rate=80.0,
            min_cmdline_rate=10.0,
            min_path_rate=10.0,
            min_precision=70.0,
            min_recall=80.0,
            min_f1=70.0,
            min_test_support=10,
        ))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["sections"]["model_deploy_gate"]["status"], "skipped")

    def test_dataset_blocks_on_low_truth_match(self):
        section = p2.check_dataset(
            {"record_count": 10, "event_source_count": 10, "label_summary": {"malicious": 1, "benign": 9}, "quality": {"truth_match_rate_percent": 0}},
            Namespace(min_graphs=1, min_source_events=1, min_malicious_graphs=1, min_benign_graphs=1, min_truth_match_rate=80.0, min_cmdline_rate=0, min_path_rate=0),
        )
        self.assertEqual(section["status"], "blocked")

    def test_legacy_manifest_computes_quality_from_events(self):
        events = self.tmp / "events.ndjson"
        normal = self.tmp / "normal.ndjson"
        truth = self.tmp / "ground_truth.jsonl"
        events.write_text(json.dumps({
            "type": "proc_exec",
            "timestamp_ns": 1_000_000_000,
            "process": {"pid": 10, "comm": "curl"},
            "payload": {"pathname": "/usr/bin/curl"},
            "enrich": {"cmdline": "curl http://127.0.0.1:1/beacon", "cmdline_source": "procfs", "cwd": "/tmp", "exe_path": "/usr/bin/curl"},
        }) + "\n", encoding="utf-8")
        normal.write_text(json.dumps({"Type": 10, "TimestampNS": 2_000_000_000, "Comm": "cat", "Pathname": "/etc/hosts"}) + "\n", encoding="utf-8")
        truth.write_text(json.dumps({
            "timestamp": "1970-01-01T00:00:01Z",
            "command": "curl",
            "malicious": True,
        }) + "\n", encoding="utf-8")
        section = p2.check_dataset(
            {"dataset_id": "legacy", "record_count": 2, "event_source_count": 2, "label_summary": {"malicious": 1, "benign": 1}},
            Namespace(
                events=[str(events)],
                normal_events=[str(normal)],
                ground_truth=[str(truth)],
                window_seconds=300,
                min_graphs=1,
                min_source_events=1,
                min_malicious_graphs=1,
                min_benign_graphs=1,
                min_truth_match_rate=80.0,
                min_cmdline_rate=0,
                min_path_rate=0,
            ),
        )
        self.assertEqual(section["status"], "pass")
        self.assertEqual(section["truth_matched_count"], 1)
        self.assertEqual(section["truth_fallback_count"], 0)
        self.assertEqual(section["truth_match_rate_percent"], 100.0)


if __name__ == "__main__":
    unittest.main()
