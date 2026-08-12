import importlib.util
import json
import shutil
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT = Path(__file__).with_name("rollout-plan.py")
SPEC = importlib.util.spec_from_file_location("rollout_plan", SCRIPT)
rollout = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(rollout)


class RolloutPlanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.cwd() / ".tmp-rollout-plan-test"
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def tearDown(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def test_builds_canary_and_waves(self):
        fleet = self.tmp / "fleet.json"
        fleet.write_text(json.dumps({"agents": [
            {"agent_id": f"a{i}", "status": "HEALTHY", "hostname": f"h{i}"}
            for i in range(1, 6)
        ]}), encoding="utf-8")
        plan = rollout.build_plan(Namespace(
            fleet=str(fleet),
            target_version="v2",
            package_path="/tmp/pkg",
            expected_sha256="abc",
            signature_path="/tmp/pkg.sig",
            canary_percent=20,
            max_batch_size=2,
            batch_by_group=False,
        ))
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["batches"][0]["name"], "canary")
        self.assertEqual(len(plan["batches"]), 3)
        self.assertEqual(plan["rollback"]["batches"][0]["name"], "wave-2")
        self.assertIn("Upgrade Rollout Plan", rollout.render_markdown(plan))

    def test_builds_group_aware_waves(self):
        fleet = self.tmp / "fleet.json"
        fleet.write_text(json.dumps({"agents": [
            {"agent_id": "a1", "status": "HEALTHY", "hostname": "h1", "group": "blue"},
            {"agent_id": "a2", "status": "HEALTHY", "hostname": "h2", "group": "blue"},
            {"agent_id": "a3", "status": "HEALTHY", "hostname": "h3", "group": "green"},
            {"agent_id": "a4", "status": "HEALTHY", "hostname": "h4", "group": "green"},
            {"agent_id": "a5", "status": "HEALTHY", "hostname": "h5", "group": "green"},
        ]}), encoding="utf-8")
        plan = rollout.build_plan(Namespace(
            fleet=str(fleet),
            target_version="v2",
            package_path="/tmp/pkg",
            expected_sha256="abc",
            signature_path="/tmp/pkg.sig",
            canary_percent=20,
            max_batch_size=2,
            batch_by_group=True,
        ))
        self.assertTrue(plan["batch_by_group"])
        self.assertEqual(plan["agent_groups"], ["blue", "green"])
        wave_groups = [batch["groups"] for batch in plan["batches"][1:]]
        self.assertIn(["blue"], wave_groups)
        self.assertIn(["green"], wave_groups)
        self.assertTrue(all(batch.get("groups") for batch in plan["rollback"]["batches"]))


if __name__ == "__main__":
    unittest.main()
