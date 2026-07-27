from __future__ import annotations

import unittest

from scripts.evaluation import augment_graph_dataset as subject


class AugmentGraphDatasetTest(unittest.TestCase):
    def test_augmented_graph_preserves_label_and_direction(self) -> None:
        base = {
            "graph_id": "base-1",
            "label": 1,
            "nodes": [
                {"id": "process:bash", "type": "process", "features": [1, 0, 0, 0, 0, 0, 1, 1]},
                {"id": "file:/tmp/payload", "type": "file", "features": [0, 1, 0, 0, 0, 1, 0, 1]},
            ],
            "edges": [{"source": "process:bash", "target": "file:/tmp/payload", "type": "file_write", "features": [0, 0, 1, 0, 0, 1]}],
        }

        graph = subject.augment_graph(base, 7, subject.random.Random(1), "test")

        self.assertEqual(graph["label"], 1)
        self.assertTrue(graph["synthetic"])
        self.assertTrue(graph["edges"][0]["source"].endswith("#sim7"))
        self.assertTrue(graph["edges"][0]["target"].endswith("#sim7"))


if __name__ == "__main__":
    unittest.main()
