import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("capture-enrichment-field-gate.py")
SPEC = importlib.util.spec_from_file_location("capture_enrichment_field_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class CaptureEnrichmentFieldGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-capture-enrichment-field-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_events(self, name, events):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
        return path

    def args(self, path, **overrides):
        values = {
            "events": [str(path)],
            "min_events": 1,
            "min_event_type_rate": 100.0,
            "min_pid_rate": 100.0,
            "min_ppid_rate": 100.0,
            "min_uid_rate": 100.0,
            "min_gid_rate": 100.0,
            "min_cmdline_rate": 50.0,
            "min_exe_path_rate": 50.0,
            "min_pathname_rate": 100.0,
            "min_network_tuple_rate": 100.0,
        }
        values.update(overrides)
        return Namespace(**values)

    def complete_events(self):
        return [
            {
                "type": "process_exec",
                "process": {"pid": 100, "ppid": 1, "uid": 1000, "gid": 1000, "cmdline": "bash -c whoami", "exe_path": "/usr/bin/bash"},
                "payload": {"cmdline": "bash -c whoami", "exe_path": "/usr/bin/bash"},
            },
            {
                "type": "file_open",
                "process": {"pid": 100, "ppid": 1, "uid": 1000, "gid": 1000, "cmdline": "cat /etc/passwd", "exe_path": "/usr/bin/cat"},
                "payload": {"pathname": "/etc/passwd"},
            },
            {
                "type": "net_connect",
                "process": {"pid": 100, "ppid": 1, "uid": 1000, "gid": 1000},
                "payload": {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3", "src_port": 38112, "dst_port": 443, "protocol": 6},
            },
            {
                "type": "setuid",
                "process": {"pid": 101, "ppid": 100, "uid": 1000, "gid": 1000, "euid": 0, "egid": 0, "cmdline": "sudo id", "exe_path": "/usr/bin/sudo"},
                "payload": {"cmdline": "sudo id", "exe_path": "/usr/bin/sudo"},
            },
        ]

    def test_passes_complete_enrichment(self):
        path = self.write_events("events.ndjson", self.complete_events())
        report = subject.build_report(self.args(path))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["summary"]["field_rates"]["network_tuple_percent"], 100.0)
        self.assertEqual(report["summary"]["scenario_counts"]["shell_activity"], 1)
        self.assertEqual(report["summary"]["scenario_counts"]["file_activity"], 1)
        self.assertEqual(report["summary"]["scenario_counts"]["network_activity"], 1)
        self.assertEqual(report["summary"]["scenario_counts"]["process_chain"], 4)
        self.assertEqual(report["summary"]["scenario_counts"]["privilege_change"], 1)

    def test_accepts_normalized_kernel_network_payload(self):
        path = self.write_events("events.ndjson", [{
            "type": "net_connect",
            "process": {"pid": 100, "ppid": 1, "uid": 1000, "gid": 1000, "cmdline": "curl http://example", "exe_path": "/usr/bin/curl"},
            "payload": {"saddr": 1, "daddr": 2, "sport": 12345, "dport": 80, "protocol": 6},
        }])
        report = subject.build_report(self.args(path, min_pathname_rate=0))
        self.assertEqual(report["summary"]["field_rates"]["network_tuple_percent"], 100.0)

    def test_blocks_missing_required_fields(self):
        path = self.write_events("events.ndjson", [{"type": "file_open", "process": {"pid": 100, "uid": 1000}, "payload": {}}])
        report = subject.build_report(self.args(path))
        self.assertEqual(report["status"], "blocked")
        text = "\n".join(report["failures"])
        self.assertIn("ppid_percent", text)
        self.assertIn("pathname_percent", text)

    def test_directory_input_discovers_jsonl_and_ndjson(self):
        self.write_events("captures/a.ndjson", [self.complete_events()[0]])
        self.write_events("captures/b.jsonl", [self.complete_events()[1], self.complete_events()[2]])
        report = subject.build_report(self.args(self.tmp / "captures"))
        self.assertEqual(report["summary"]["event_count"], 3)

    def test_warns_when_behavior_scenarios_are_missing(self):
        path = self.write_events("events.ndjson", [{
            "type": "process_exec",
            "process": {"pid": 100, "ppid": 1, "uid": 1000, "gid": 1000, "cmdline": "id", "exe_path": "/usr/bin/id"},
            "payload": {"cmdline": "id", "exe_path": "/usr/bin/id"},
        }])
        report = subject.build_report(self.args(path, min_pathname_rate=0, min_network_tuple_rate=0))
        self.assertEqual(report["status"], "warn")
        text = "\n".join(report["warnings"])
        self.assertIn("shell activity", text)
        self.assertIn("file activity", text)
        self.assertIn("network activity", text)


if __name__ == "__main__":
    unittest.main()
