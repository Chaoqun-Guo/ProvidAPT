import importlib.util
import json
import shutil
import time
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("collect-soak-sample.py")
SPEC = importlib.util.spec_from_file_location("collect_soak_sample", SCRIPT)
collector = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(collector)


class CollectSoakSampleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-soak-sample-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_build_sample_normalizes_status_fields(self):
        started = time.time() - 7200
        sample = collector.build_sample({
            "agent_id": "agent-a",
            "metrics": {
                "cpu_percent": 12.5,
                "memory_bytes": 268435456,
                "log_disk_bytes": 536870912,
                "events_ingested": 42,
                "events_dropped": 0,
                "graph_nodes": 5,
                "graph_edges": 7,
            },
            "runtime": {"queue_depth": 3},
        }, started)
        self.assertEqual(sample["host"], "agent-a")
        self.assertEqual(sample["memory_mb"], 256)
        self.assertEqual(sample["disk_mb"], 512)
        self.assertGreaterEqual(sample["duration_hours"], 1.9)

    def test_build_sample_uses_status_uptime_when_start_epoch_missing(self):
        sample = collector.build_sample({
            "hostname": "control",
            "uptime_seconds": 25 * 3600,
            "memory_bytes": 104857600,
            "events_dropped": 0,
        }, 0)
        self.assertEqual(sample["host"], "control")
        self.assertEqual(sample["duration_hours"], 25)
        self.assertEqual(sample["memory_mb"], 100)

    def test_append_sample_preserves_existing_rows(self):
        out = self.tmp / "samples.json"
        out.write_text(json.dumps({"samples": [{"host": "old"}]}), encoding="utf-8")
        report = collector.append_sample(out, {"host": "new"})
        self.assertEqual(len(report["samples"]), 2)
        self.assertEqual(report["schema"], collector.SCHEMA)

    def test_collect_samples_supports_accelerated_batching(self):
        out = self.tmp / "samples.json"
        status = self.tmp / "status.json"
        status.write_text(json.dumps({
            "hostname": "vm-control",
            "uptime_seconds": 300,
            "memory_bytes": 1048576,
            "events_ingested": 10,
        }), encoding="utf-8")
        report = collector.collect_samples(
            status_url="",
            status_json=str(status),
            host="",
            started_at_epoch=0,
            out=out,
            count=3,
            interval_seconds=0,
        )
        self.assertEqual(len(report["samples"]), 3)
        self.assertEqual({sample["host"] for sample in report["samples"]}, {"vm-control"})

    def test_host_from_status_url_supports_short_vm_names(self):
        self.assertEqual(collector.host_from_status_url("http://vm-ubuntu-master:18080/api/v1/status"), "vm-ubuntu-master")
        self.assertEqual(collector.host_from_status_url("not a url"), "")


if __name__ == "__main__":
    unittest.main()
