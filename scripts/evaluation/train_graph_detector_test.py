from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluation import train_graph_detector as subject


class TrainGraphDetectorTest(unittest.TestCase):
    def test_loads_graphs_and_splits_fallbacks(self) -> None:
        root = Path.cwd() / "build" / "unit-tmp" / "graph-train"
        root.mkdir(parents=True, exist_ok=True)
        path = root / "graphs.jsonl"
        rows = [
            {"graph_id": "g1", "split": "train", "label": 0, "nodes": [{"id": "process:1", "features": [1, 0, 0, 0, 0, 0, 1, 1]}], "edges": []},
            {"graph_id": "g2", "split": "test", "label": 1, "nodes": [{"id": "process:2", "features": [1, 0, 0, 0, 0, 0, 1, 1]}], "edges": []},
        ]
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

        graphs = subject.load_graphs(path)
        groups = subject.split_graphs(graphs)

        self.assertEqual(len(graphs), 2)
        self.assertEqual(len(groups["train"]), 1)
        self.assertEqual(len(groups["test"]), 1)
        self.assertEqual(len(groups["val"]), 1)

    def test_auc_helpers_handle_separable_scores(self) -> None:
        labels = [0, 0, 1, 1]
        scores = [0.1, 0.2, 0.8, 0.9]

        self.assertEqual(subject.roc_auc(labels, scores), 1.0)
        self.assertEqual(subject.pr_auc(labels, scores), 1.0)

    @unittest.skipIf(subject.torch is None, "PyTorch is not installed")
    def test_graph_to_tensors_preserves_shape(self) -> None:
        graph = {
            "label": 1,
            "nodes": [
                {"id": "process:1", "features": [1, 0, 0, 0, 0, 0, 1, 1]},
                {"id": "file:/tmp/x", "features": [0, 1, 0, 0, 0, 1, 0, 1]},
            ],
            "edges": [{"source": "process:1", "target": "file:/tmp/x", "type": "file_write"}],
        }

        x, adjacency, label = subject.graph_to_tensors(subject.torch, graph)

        self.assertEqual(tuple(x.shape), (2, 8))
        self.assertEqual(tuple(adjacency.shape), (2, 2))
        self.assertEqual(float(label.item()), 1.0)


if __name__ == "__main__":
    unittest.main()
