import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("customer-release-gate.py")
SPEC = importlib.util.spec_from_file_location("customer_release_gate", SCRIPT)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class CustomerReleaseGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / "build" / "unit-tmp" / "customer-release-gate"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir(parents=True)

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def write_json(self, name, value):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def write_text(self, name, value="ok\n"):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        return path

    def make_args(self, **overrides):
        values = {
            "release_gates": str(self.write_json("release-gates.json", {"gates": [{"name": "ci", "status": "pass"}]})),
            "dist_dir": str(self.tmp / "dist"),
            "package_smoke_dir": str(self.tmp / "package-smoke"),
            "production_readiness_gate": str(self.write_json("production.json", {"status": "pass"})),
            "ml_readiness_gate": str(self.write_json("ml.json", {"status": "pass"})),
            "operations_readiness_gate": str(self.write_json("operations.json", {"status": "pass"})),
            "commercialization_readiness_gate": str(self.write_json("commercialization.json", {"status": "pass"})),
            "legal_doc": [str(self.write_text("legal.md", "approved\n"))],
            "delivery_doc": [str(self.write_text("delivery.md", "approved\n"))],
            "allow_skipped_ci": False,
        }
        values.update(overrides)
        return Namespace(**values)

    def populate_dist_and_smoke(self):
        dist = self.tmp / "dist"
        smoke = self.tmp / "package-smoke"
        dist.mkdir(parents=True, exist_ok=True)
        smoke.mkdir(parents=True, exist_ok=True)
        for name in [
            "providapt.tar.gz",
            "providapt.deb",
            "providapt.rpm",
            "providapt-helm.tgz",
            "sbom.spdx.json",
            "sbom.cdx.json",
            "checksums.txt",
            "checksums.txt.sig",
            "release-readiness.md",
        ]:
            (dist / name).write_text("x\n", encoding="utf-8")
        for name in ["deb-config-check.txt", "rpm-info.txt", "tar-providaptctl-path.txt"]:
            (smoke / name).write_text("x\n", encoding="utf-8")

    def test_build_report_passes_with_complete_evidence(self):
        self.populate_dist_and_smoke()
        report = subject.build_report(self.make_args())
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["sections"]["dist_artifacts"]["status"], "pass")
        self.assertIn("Customer Release Gate", subject.render_markdown(report))

    def test_build_report_blocks_on_missing_dist_artifact(self):
        self.populate_dist_and_smoke()
        (self.tmp / "dist" / "checksums.txt.sig").unlink()
        report = subject.build_report(self.make_args())
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["sections"]["dist_artifacts"]["status"], "blocked")

    def test_skipped_ci_can_be_controlled_warning(self):
        self.populate_dist_and_smoke()
        release_gates = self.write_json("release-gates-skipped.json", {"gates": [{"name": "github_actions", "status": "skipped"}]})
        blocked = subject.build_report(self.make_args(release_gates=str(release_gates), allow_skipped_ci=False))
        warned = subject.build_report(self.make_args(release_gates=str(release_gates), allow_skipped_ci=True))
        self.assertEqual(blocked["sections"]["release_gates"]["status"], "blocked")
        self.assertEqual(warned["sections"]["release_gates"]["status"], "warn")


if __name__ == "__main__":
    unittest.main()
