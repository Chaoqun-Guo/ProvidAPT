#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import torch
    from torch import nn
except ImportError:  # pragma: no cover - exercised by CLI message path.
    torch = None
    nn = None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_graphs(path: Path) -> list[dict[str, Any]]:
    graphs: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if isinstance(item, dict):
                graphs.append(item)
    if not graphs:
        raise SystemExit(f"{path}: no graphs found")
    return graphs


def scale_feature(index: int, value: float, transform: str) -> float:
    if transform == "log1p" and index >= 5:
        import math

        return math.log1p(max(0.0, value))
    return value


def graph_to_tensors(torch: Any, graph: dict[str, Any], device: str | None = None, feature_transform: str = "none") -> tuple[Any, Any, Any]:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not isinstance(nodes, list) or not nodes:
        nodes = [{"id": "empty:0", "type": "unknown", "features": [0.0] * 8}]
    node_ids = [str(node.get("id", index)) for index, node in enumerate(nodes)]
    node_index = {node_id: index for index, node_id in enumerate(node_ids)}
    features = []
    for node in nodes:
        row = node.get("features") if isinstance(node, dict) else None
        if not isinstance(row, list) or not row:
            row = [0.0] * 8
        features.append([scale_feature(index, float(value or 0.0), feature_transform) for index, value in enumerate(row)])
    x = torch.tensor(features, dtype=torch.float32, device=device)
    adjacency = torch.eye(len(nodes), dtype=torch.float32, device=device)
    if isinstance(edges, list):
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            src = node_index.get(str(edge.get("source", "")))
            dst = node_index.get(str(edge.get("target", "")))
            if src is None or dst is None:
                continue
            adjacency[src, dst] = 1.0
            adjacency[dst, src] = 1.0
    label = torch.tensor([float(graph.get("label", 0))], dtype=torch.float32, device=device)
    return x, adjacency, label


def graph_batch_to_tensors(torch: Any, graphs: list[dict[str, Any]], device: str | None = None, feature_transform: str = "none") -> tuple[Any, Any, Any, Any, int]:
    feature_rows: list[list[float]] = []
    edge_pairs: list[tuple[int, int]] = []
    graph_indexes: list[int] = []
    labels: list[float] = []
    offset = 0
    for graph_index, graph in enumerate(graphs):
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        if not isinstance(nodes, list) or not nodes:
            nodes = [{"id": "empty:0", "type": "unknown", "features": [0.0] * 8}]
        node_ids = [str(node.get("id", index)) for index, node in enumerate(nodes)]
        node_index = {node_id: offset + index for index, node_id in enumerate(node_ids)}
        for node in nodes:
            row = node.get("features") if isinstance(node, dict) else None
            if not isinstance(row, list) or not row:
                row = [0.0] * 8
            feature_rows.append([scale_feature(index, float(value or 0.0), feature_transform) for index, value in enumerate(row)])
            graph_indexes.append(graph_index)
        for index in range(len(nodes)):
            edge_pairs.append((offset + index, offset + index))
        if isinstance(edges, list):
            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                src = node_index.get(str(edge.get("source", "")))
                dst = node_index.get(str(edge.get("target", "")))
                if src is None or dst is None:
                    continue
                edge_pairs.append((src, dst))
                edge_pairs.append((dst, src))
        labels.append(float(graph.get("label", 0)))
        offset += len(nodes)
    x = torch.tensor(feature_rows, dtype=torch.float32, device=device)
    adjacency = torch.zeros((len(feature_rows), len(feature_rows)), dtype=torch.float32, device=device)
    if edge_pairs:
        src = torch.tensor([pair[0] for pair in edge_pairs], dtype=torch.long, device=device)
        dst = torch.tensor([pair[1] for pair in edge_pairs], dtype=torch.long, device=device)
        adjacency[src, dst] = 1.0
    label = torch.tensor(labels, dtype=torch.float32, device=device)
    graph_index_tensor = torch.tensor(graph_indexes, dtype=torch.long, device=device)
    return x, adjacency, label, graph_index_tensor, len(graphs)


class _GraphClassifier(nn.Module if nn is not None else object):
    def __init__(self, input_dim: int, hidden_dim: int, architecture: str, heads: int) -> None:
        if nn is None:
            raise RuntimeError("PyTorch is required")
        super().__init__()
        self.architecture = architecture
        if architecture == "gat":
            self.layer1 = nn.Linear(input_dim, hidden_dim * heads)
            self.attn = nn.Linear(hidden_dim * heads * 2, heads)
            self.layer2 = nn.Linear(hidden_dim * heads, hidden_dim)
        elif architecture == "graphsage":
            self.layer1 = nn.Linear(input_dim * 2, hidden_dim)
            self.layer2 = nn.Linear(hidden_dim * 2, hidden_dim)
        elif architecture == "mlp":
            self.layer1 = nn.Linear(input_dim, hidden_dim)
            self.layer2 = nn.Linear(hidden_dim, hidden_dim)
        else:
            self.layer1 = nn.Linear(input_dim, hidden_dim)
            self.layer2 = nn.Linear(hidden_dim, hidden_dim)
        self.out = nn.Linear(hidden_dim, 1)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.15)

    def normalized_adjacency(self, adjacency: Any) -> Any:
        degree = adjacency.sum(dim=1).clamp(min=1.0)
        inv_sqrt = degree.pow(-0.5)
        return inv_sqrt.unsqueeze(1) * adjacency * inv_sqrt.unsqueeze(0)

    def mean_aggregate(self, x: Any, adjacency: Any) -> Any:
        degree = adjacency.sum(dim=1).clamp(min=1.0).unsqueeze(1)
        return adjacency.matmul(x) / degree

    def gat_aggregate(self, h: Any, adjacency: Any) -> Any:
        node_count = h.shape[0]
        left = h.unsqueeze(1).repeat(1, node_count, 1)
        right = h.unsqueeze(0).repeat(node_count, 1, 1)
        scores = self.attn(torch.cat([left, right], dim=-1)).mean(dim=-1)
        scores = scores.masked_fill(adjacency <= 0, -1e9)
        weights = torch.softmax(scores, dim=1)
        return weights.matmul(h)

    def forward(self, x: Any, adjacency: Any, graph_index: Any | None = None, graph_count: int | None = None) -> Any:
        if self.architecture == "mlp":
            h = self.relu(self.layer1(x))
            h = self.dropout(self.relu(self.layer2(h)))
        elif self.architecture == "gat":
            h = self.relu(self.layer1(x))
            h = self.dropout(self.relu(self.layer2(self.gat_aggregate(h, adjacency))))
        elif self.architecture == "graphsage":
            h = self.relu(self.layer1(torch.cat([x, self.mean_aggregate(x, adjacency)], dim=1)))
            h = self.dropout(self.relu(self.layer2(torch.cat([h, self.mean_aggregate(h, adjacency)], dim=1))))
        else:
            norm = self.normalized_adjacency(adjacency)
            h = self.relu(self.layer1(norm.matmul(x)))
            h = self.dropout(self.relu(self.layer2(norm.matmul(h))))
        if graph_index is None:
            pooled = h.mean(dim=0)
            return self.out(pooled).view(1)
        if graph_count is None:
            graph_count = int(graph_index.max().item()) + 1 if graph_index.numel() else 1
        pooled = torch.zeros((graph_count, h.shape[1]), dtype=h.dtype, device=h.device)
        pooled.index_add_(0, graph_index, h)
        counts = torch.bincount(graph_index, minlength=graph_count).clamp(min=1).to(dtype=h.dtype).unsqueeze(1)
        pooled = pooled / counts
        return self.out(pooled).view(graph_count)


def split_graphs(graphs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups = {"train": [], "val": [], "test": []}
    for graph in graphs:
        split = str(graph.get("split") or "train")
        groups.setdefault(split, []).append(graph)
    if not groups["train"]:
        groups["train"] = graphs
    if not groups["test"]:
        groups["test"] = groups.get("val") or graphs
    if not groups["val"]:
        groups["val"] = groups["test"]
    return groups


def limit_graphs(rows: list[dict[str, Any]], limit: int, seed: int) -> list[dict[str, Any]]:
    if limit <= 0 or len(rows) <= limit:
        return rows
    positives = [graph for graph in rows if int(graph.get("label") or 0) == 1]
    negatives = [graph for graph in rows if int(graph.get("label") or 0) != 1]
    keep_negative = max(0, limit - len(positives))
    if keep_negative >= len(negatives):
        selected = positives + negatives
    else:
        rng = random.Random(seed)
        selected = positives + rng.sample(negatives, keep_negative)
    return sorted(selected, key=lambda graph: str(graph.get("graph_id") or ""))


def chunks(rows: list[dict[str, Any]], size: int) -> Any:
    if size <= 1:
        for row in rows:
            yield [row]
        return
    for index in range(0, len(rows), size):
        yield rows[index:index + size]


def roc_auc(labels: list[int], scores: list[float]) -> float:
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return 0.0
    ranked = sorted(zip(scores, labels), key=lambda item: item[0])
    rank_sum = 0.0
    index = 0
    while index < len(ranked):
        end = index + 1
        while end < len(ranked) and ranked[end][0] == ranked[index][0]:
            end += 1
        average_rank = (index + 1 + end) / 2.0
        rank_sum += sum(label for _score, label in ranked[index:end]) * average_rank
        index = end
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def pr_auc(labels: list[int], scores: list[float]) -> float:
    positives = sum(labels)
    if positives == 0:
        return 0.0
    pairs = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    tp = fp = 0
    previous_recall = 0.0
    area = 0.0
    for _score, label in pairs:
        if label:
            tp += 1
        else:
            fp += 1
        recall = tp / positives
        precision = tp / max(1, tp + fp)
        area += precision * max(0.0, recall - previous_recall)
        previous_recall = recall
    return area


def predict_probabilities(torch: Any, model: _GraphClassifier, rows: list[dict[str, Any]], device: str | None, feature_transform: str, batch_size: int) -> tuple[list[int], list[float]]:
    labels: list[int] = []
    probabilities: list[float] = []
    model.eval()
    with torch.no_grad():
        for batch in chunks(rows, batch_size):
            if batch_size <= 1:
                x, adjacency, label = graph_to_tensors(torch, batch[0], device, feature_transform)
                logits = model(x, adjacency)
            else:
                x, adjacency, label, graph_index, graph_count = graph_batch_to_tensors(torch, batch, device, feature_transform)
                logits = model(x, adjacency, graph_index, graph_count)
            probabilities.extend(float(value) for value in torch.sigmoid(logits).detach().cpu().tolist())
            labels.extend(int(value) for value in label.detach().cpu().tolist())
    return labels, probabilities


def best_f1_threshold(labels: list[int], probabilities: list[float]) -> tuple[float, float]:
    best_threshold = 0.5
    best_f1 = -1.0
    for step in range(1, 1000):
        threshold = step / 1000.0
        tp = fp = fn = 0
        for label, probability in zip(labels, probabilities):
            prediction = 1 if probability >= threshold else 0
            if prediction == 1 and label == 1:
                tp += 1
            elif prediction == 1:
                fp += 1
            elif label == 1:
                fn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
    return best_threshold, best_f1


def evaluate(torch: Any, model: _GraphClassifier, rows: list[dict[str, Any]], score_limit: int = 5000, device: str | None = None, feature_transform: str = "none", batch_size: int = 1, threshold: float = 0.5) -> dict[str, Any]:
    model.eval()
    tp = fp = tn = fn = 0
    scores = []
    all_scores: list[float] = []
    labels: list[int] = []
    with torch.no_grad():
        for batch in chunks(rows, batch_size):
            if batch_size <= 1:
                x, adjacency, label = graph_to_tensors(torch, batch[0], device, feature_transform)
                logits = model(x, adjacency)
            else:
                x, adjacency, label, graph_index, graph_count = graph_batch_to_tensors(torch, batch, device, feature_transform)
                logits = model(x, adjacency, graph_index, graph_count)
            probabilities = torch.sigmoid(logits).detach().cpu().tolist()
            expected_values = label.detach().cpu().tolist()
            for graph, probability, expected_value in zip(batch, probabilities, expected_values):
                prediction = 1 if probability >= threshold else 0
                expected = int(expected_value)
                all_scores.append(float(probability))
                labels.append(expected)
                if len(scores) < score_limit:
                    scores.append({"graph_id": graph.get("graph_id", ""), "label": expected, "score": round(float(probability), 6), "prediction": prediction})
                if prediction == 1 and expected == 1:
                    tp += 1
                elif prediction == 1:
                    fp += 1
                elif expected == 1:
                    fn += 1
                else:
                    tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    npv = tn / (tn + fn) if tn + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
    denominator = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = ((tp * tn - fp * fn) / denominator) if denominator else 0.0
    return {
        "support": len(rows),
        "threshold": threshold,
        "accuracy_percent": round(accuracy * 100.0, 2),
        "precision_percent": round(precision * 100.0, 2),
        "recall_percent": round(recall * 100.0, 2),
        "specificity_percent": round(specificity * 100.0, 2),
        "negative_predictive_value_percent": round(npv * 100.0, 2),
        "f1_percent": round(f1 * 100.0, 2),
        "balanced_accuracy_percent": round(((recall + specificity) / 2.0) * 100.0, 2),
        "mcc": round(mcc, 6),
        "false_positive_rate_percent": round((1.0 - specificity) * 100.0, 2),
        "false_negative_rate_percent": round((1.0 - recall) * 100.0, 2),
        "roc_auc_percent": round(roc_auc(labels, all_scores) * 100.0, 2),
        "pr_auc_percent": round(pr_auc(labels, all_scores) * 100.0, 2),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "score_count": len(all_scores),
        "score_sample": scores,
    }


def train(args: argparse.Namespace) -> dict[str, Any]:
    if torch is None or nn is None:
        raise SystemExit("PyTorch is required. Run with: conda run -n torch_py39 python scripts/evaluation/train_graph_detector.py ...")

    torch.manual_seed(args.seed)
    if args.device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    else:
        device = args.device
    if device == "cuda" and not torch.cuda.is_available():
        raise SystemExit("CUDA was requested but is not available in the torch_py39 environment")
    graphs = load_graphs(Path(args.dataset))
    groups = split_graphs(graphs)
    original_split_summary = {key: len(value) for key, value in groups.items()}
    groups["train"] = limit_graphs(groups["train"], args.max_train_graphs, args.seed)
    groups["val"] = limit_graphs(groups["val"], args.max_val_graphs, args.seed + 1)
    groups["test"] = limit_graphs(groups["test"], args.max_test_graphs, args.seed + 2)
    first_x, _, _ = graph_to_tensors(torch, graphs[0], device, args.feature_transform)
    model = _GraphClassifier(first_x.shape[1], args.hidden_dim, args.architecture, args.heads).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    train_positive = sum(1 for graph in groups["train"] if int(graph.get("label") or 0) == 1)
    train_negative = max(0, len(groups["train"]) - train_positive)
    if args.pos_weight == "auto":
        positive_weight = train_negative / max(1, train_positive)
    elif args.pos_weight == "none":
        positive_weight = 1.0
    else:
        positive_weight = float(args.pos_weight)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([positive_weight], dtype=torch.float32, device=device))
    history = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        train_rows = list(groups["train"])
        random.Random(args.seed + epoch).shuffle(train_rows)
        for batch in chunks(train_rows, args.batch_size):
            if args.batch_size <= 1:
                x, adjacency, label = graph_to_tensors(torch, batch[0], device, args.feature_transform)
                logits = model(x, adjacency)
            else:
                x, adjacency, label, graph_index, graph_count = graph_batch_to_tensors(torch, batch, device, args.feature_transform)
                logits = model(x, adjacency, graph_index, graph_count)
            optimizer.zero_grad()
            loss = loss_fn(logits, label)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item()) * len(batch)
        val_metrics = evaluate(torch, model, groups["val"], args.score_limit, device, args.feature_transform, args.batch_size)
        history.append({
            "epoch": epoch,
            "loss": round(total_loss / max(1, len(train_rows)), 6),
            "val_f1_percent": val_metrics["f1_percent"],
            "val_accuracy_percent": val_metrics["accuracy_percent"],
            "val_precision_percent": val_metrics["precision_percent"],
            "val_recall_percent": val_metrics["recall_percent"],
        })
    if args.threshold == "auto":
        val_labels, val_probabilities = predict_probabilities(torch, model, groups["val"], device, args.feature_transform, args.batch_size)
        threshold, val_best_f1 = best_f1_threshold(val_labels, val_probabilities)
    else:
        threshold = float(args.threshold)
        val_best_f1 = 0.0
    train_metrics = evaluate(torch, model, groups["train"], args.score_limit, device, args.feature_transform, args.batch_size, threshold)
    val_metrics = evaluate(torch, model, groups["val"], args.score_limit, device, args.feature_transform, args.batch_size, threshold)
    test_metrics = evaluate(torch, model, groups["test"], args.score_limit, device, args.feature_transform, args.batch_size, threshold)
    label_counts = Counter(str(graph.get("label_name") or graph.get("label")) for graph in graphs)
    report = {
        "schema": "providapt.graph_detector_training.v1",
        "generated_at": utc_now(),
        "architecture": args.architecture,
        "device": device,
        "feature_transform": args.feature_transform,
        "epochs": args.epochs,
        "hidden_dim": args.hidden_dim,
        "positive_weight": round(float(positive_weight), 6),
        "batch_size": args.batch_size,
        "threshold": round(float(threshold), 6),
        "val_best_f1_percent": round(val_best_f1 * 100.0, 2),
        "dataset": str(args.dataset),
        "dataset_records": len(graphs),
        "label_summary": dict(label_counts),
        "original_split_summary": original_split_summary,
        "split_summary": {key: len(value) for key, value in groups.items()},
        "history": history,
        "train_metrics": train_metrics,
        "val_metrics": val_metrics,
        "test_metrics": test_metrics,
        **test_metrics,
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    torch.save({
        "state_dict": model.state_dict(),
        "metadata": {key: value for key, value in report.items() if key != "scores"},
    }, out_dir / "model.pt")
    (out_dir / "metrics.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "metrics.md").write_text(render_metrics(report), encoding="utf-8")
    (out_dir / "model-card.md").write_text(render_model_card(report), encoding="utf-8")
    return report


def render_metrics(report: dict[str, Any]) -> str:
    return "\n".join([
        "# ProvidAPT Graph Detector Metrics",
        "",
        f"- Architecture: `{report['architecture']}`",
        f"- Device: `{report['device']}`",
        f"- Dataset records: `{report['dataset_records']}`",
        f"- Accuracy: `{report['accuracy_percent']}%`",
        f"- Precision: `{report['precision_percent']}%`",
        f"- Recall: `{report['recall_percent']}%`",
        f"- Specificity: `{report['specificity_percent']}%`",
        f"- F1: `{report['f1_percent']}%`",
        f"- Balanced accuracy: `{report['balanced_accuracy_percent']}%`",
        f"- ROC AUC: `{report['roc_auc_percent']}%`",
        f"- PR AUC: `{report['pr_auc_percent']}%`",
        f"- MCC: `{report['mcc']}`",
        f"- Confusion: `tp={report['confusion']['tp']} fp={report['confusion']['fp']} tn={report['confusion']['tn']} fn={report['confusion']['fn']}`",
        "",
    ])


def render_model_card(report: dict[str, Any]) -> str:
    return "\n".join([
        "# ProvidAPT Graph Detector Model Card",
        "",
        "## Intended Use",
        "",
        "This model classifies small provenance subgraphs as benign or ATT&CK-aligned suspicious activity.",
        "",
        "## Architecture",
        "",
        f"- Family: `{report['architecture']}`",
        f"- Device: `{report['device']}`",
        f"- Hidden dimension: `{report['hidden_dim']}`",
        f"- Training epochs: `{report['epochs']}`",
        "",
        "## Validation",
        "",
        f"- Accuracy: `{report['accuracy_percent']}%`",
        f"- Precision: `{report['precision_percent']}%`",
        f"- Recall: `{report['recall_percent']}%`",
        f"- F1: `{report['f1_percent']}%`",
        f"- ROC AUC: `{report['roc_auc_percent']}%`",
        f"- PR AUC: `{report['pr_auc_percent']}%`",
        "",
        "## Operational Notes",
        "",
        "- Gate deployment with `make model-deploy-gate` before promoting the artifact.",
        "- Retrain after capture schema changes or ATT&CK simulation coverage changes.",
        "",
    ])


def main() -> int:
    parser = argparse.ArgumentParser(description="Train a lightweight graph detector using PyTorch.")
    parser.add_argument("--dataset", default="build/ml-dataset/graphs.jsonl")
    parser.add_argument("--out-dir", default="build/ml-model")
    parser.add_argument("--architecture", choices=["gcn", "gat", "graphsage", "mlp"], default="gcn")
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--hidden-dim", type=int, default=32)
    parser.add_argument("--heads", type=int, default=2)
    parser.add_argument("--lr", type=float, default=0.01)
    parser.add_argument("--weight-decay", type=float, default=0.0005)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--score-limit", type=int, default=5000)
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    parser.add_argument("--pos-weight", default="auto", help="BCE positive class weight: auto, none, or numeric value")
    parser.add_argument("--max-train-graphs", type=int, default=0, help="Optional stratified cap for train graphs; all positive graphs are retained")
    parser.add_argument("--max-val-graphs", type=int, default=0, help="Optional stratified cap for validation graphs; all positive graphs are retained")
    parser.add_argument("--max-test-graphs", type=int, default=0, help="Optional stratified cap for test graphs; all positive graphs are retained")
    parser.add_argument("--feature-transform", choices=["none", "log1p"], default="none")
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--threshold", default="0.5", help="Decision threshold, or auto to maximize validation F1")
    args = parser.parse_args()
    report = train(args)
    print(f"architecture={report['architecture']} f1={report['f1_percent']} out={args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
