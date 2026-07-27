#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.graph_training_dataset.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
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
                rows.append(item)
    if not rows:
        raise SystemExit(f"{path}: no graph records found")
    return rows


def split_for(graph_id: str, seed: str) -> str:
    bucket = int(hashlib.sha256(f"{seed}|{graph_id}".encode("utf-8")).hexdigest()[:8], 16) / 0xFFFFFFFF
    if bucket < 0.70:
        return "train"
    if bucket < 0.85:
        return "val"
    return "test"


def jitter_features(values: Any, rng: random.Random, label: int) -> list[float]:
    if not isinstance(values, list):
        return []
    out: list[float] = []
    for index, value in enumerate(values):
        try:
            numeric = float(value or 0.0)
        except (TypeError, ValueError):
            numeric = 0.0
        if index >= 5:
            numeric = max(0.0, numeric + rng.choice([0.0, 0.0, 1.0, 2.0]) + (1.0 if label else 0.0))
        out.append(round(numeric, 4))
    return out


def augment_graph(base: dict[str, Any], index: int, rng: random.Random, split_seed: str) -> dict[str, Any]:
    label = int(base.get("label") or 0)
    graph_id = f"aug-{index:06d}-{base.get('graph_id', 'graph')}"
    id_map: dict[str, str] = {}
    nodes = []
    for node in base.get("nodes", []):
        if not isinstance(node, dict):
            continue
        old_id = str(node.get("id") or f"node:{len(nodes)}")
        new_id = f"{old_id}#sim{index}"
        id_map[old_id] = new_id
        nodes.append({
            "id": new_id,
            "type": node.get("type", "unknown"),
            "features": jitter_features(node.get("features"), rng, label),
        })
    edges = []
    for edge in base.get("edges", []):
        if not isinstance(edge, dict):
            continue
        src = id_map.get(str(edge.get("source") or ""), str(edge.get("source") or "unknown"))
        dst = id_map.get(str(edge.get("target") or ""), str(edge.get("target") or "unknown"))
        edges.append({
            "source": src,
            "target": dst,
            "type": edge.get("type", "observed"),
            "features": jitter_features(edge.get("features"), rng, label),
        })
    if label and nodes and rng.random() < 0.18:
        beacon = f"network:synthetic-c2-{index % 2048}.example:443#sim{index}"
        nodes.append({"id": beacon, "type": "network", "features": [0, 0, 1, 0, 0, 1, 0, 1 + index % 5]})
        process_nodes = [node["id"] for node in nodes if node.get("type") == "process"]
        if process_nodes:
            edges.append({"source": rng.choice(process_nodes), "target": beacon, "type": "network", "features": [0, 0, 0, 1, 0, 1 + index % 4]})
    graph = {
        **base,
        "schema": SCHEMA,
        "graph_id": graph_id,
        "split": split_for(graph_id, split_seed),
        "label": label,
        "label_name": "malicious" if label else "benign",
        "event_count": int(base.get("event_count") or 1) + rng.randint(0, 8),
        "nodes": nodes,
        "edges": edges,
        "synthetic": True,
        "synthetic_source_graph_id": base.get("graph_id", ""),
    }
    return graph


def build_manifest(args: argparse.Namespace, counts: Counter[str], split_counts: dict[str, Counter[str]], source_manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "dataset_version": args.dataset_version,
        "dataset_id": "graphaug-" + hashlib.sha256(f"{args.seed}|{args.records}|{args.input}".encode("utf-8")).hexdigest()[:16],
        "record_count": args.records,
        "synthetic": True,
        "augmentation": {
            "method": "deterministic_graph_jitter",
            "seed": args.seed,
            "source_dataset": str(args.input),
            "source_dataset_id": source_manifest.get("dataset_id", ""),
            "source_records": source_manifest.get("record_count", 0),
        },
        "label_summary": dict(counts),
        "split_summary": {key: dict(value) for key, value in sorted(split_counts.items())},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a large deterministic synthetic graph dataset from captured ProvidAPT graph labels.")
    parser.add_argument("--input", default="build/ml-dataset/graphs.jsonl")
    parser.add_argument("--source-manifest", default="")
    parser.add_argument("--feature-schema", default="")
    parser.add_argument("--out-dir", default="build/ml-dataset-large")
    parser.add_argument("--records", type=int, default=200_000)
    parser.add_argument("--dataset-version", default="synthetic-large")
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--split-seed", default="providapt-large")
    args = parser.parse_args()

    base = load_jsonl(Path(args.input))
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    source_manifest = {}
    if args.source_manifest and Path(args.source_manifest).exists():
        source_manifest = json.loads(Path(args.source_manifest).read_text(encoding="utf-8"))
    counts: Counter[str] = Counter()
    split_counts: dict[str, Counter[str]] = defaultdict(Counter)
    rng = random.Random(args.seed)
    with (out_dir / "graphs.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for index in range(args.records):
            graph = augment_graph(base[index % len(base)], index, rng, args.split_seed)
            counts[graph["label_name"]] += 1
            split_counts[graph["split"]]["total"] += 1
            split_counts[graph["split"]][graph["label_name"]] += 1
            handle.write(json.dumps(graph, sort_keys=True, ensure_ascii=False) + "\n")
    manifest = build_manifest(args, counts, split_counts, source_manifest)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.feature_schema and Path(args.feature_schema).exists():
        (out_dir / "feature_schema.json").write_text(Path(args.feature_schema).read_text(encoding="utf-8"), encoding="utf-8")
    print(f"records={args.records} out={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
