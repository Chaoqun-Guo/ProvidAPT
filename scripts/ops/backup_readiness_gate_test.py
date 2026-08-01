import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("backup-readiness-gate.py")
SPEC = importlib.util.spec_from_file_location("backup_readiness_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class BackupReadinessGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-backup-readiness-gate-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def args(self, path, **overrides):
        values = {
            "backup_summary": str(path),
            "min_backup_bytes": 1,
            "require_restore": True,
            "require_cutover": True,
            "require_download": True,
        }
        values.update(overrides)
        return Namespace(**values)

    def complete_summary(self):
        return {
            "last_backup_path": "/var/lib/providapt/backups/providapt.tar.gz",
            "last_restore_path": "/var/lib/providapt/restore-staging",
            "last_status": "created",
            "size_bytes": 4096,
            "download_url": "/api/v1/control/backup/download",
            "history": [
                {"action": "backup_create", "status": "created"},
                {"action": "backup_restore_staging", "status": "restored_staging"},
                {"action": "backup_prepare_cutover", "status": "cutover_ready"},
            ],
        }

    def test_passes_complete_backup_evidence(self):
        path = self.write_json("backup.json", self.complete_summary())
        report = subject.build_report(self.args(path))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["history_count"], 3)

    def test_blocks_missing_restore(self):
        summary = self.complete_summary()
        summary["last_restore_path"] = ""
        summary["history"] = [summary["history"][0]]
        path = self.write_json("backup.json", summary)
        report = subject.build_report(self.args(path))
        self.assertEqual(report["status"], "blocked")
        self.assertIn("restore staging", "\n".join(report["failures"]))

    def test_warns_on_empty_history_when_optional(self):
        summary = self.complete_summary()
        summary["history"] = []
        path = self.write_json("backup.json", summary)
        report = subject.build_report(self.args(path, require_restore=False, require_cutover=False))
        self.assertEqual(report["status"], "warn")


if __name__ == "__main__":
    unittest.main()
