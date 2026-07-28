#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.graph_training_dataset.v1"
FEATURE_SCHEMA = "providapt.graph_feature_schema.v1"
NODE_FEATURES = [
    "is_process",
    "is_file",
    "is_network",
    "is_user",
    "is_truth",
    "in_degree",
    "out_degree",
    "event_count",
]
EDGE_FEATURES = [
    "is_exec",
    "is_file_read",
    "is_file_write",
    "is_network",
    "is_user_context",
    "event_count",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
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
                item.setdefault("_source_file", str(path))
                records.append(item)
    return records


def load_optional_jsonl(paths: list[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        records.extend(load_jsonl(path))
    return records


def iter_files(inputs: list[str], suffixes: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for value in inputs:
        path = Path(value)
        if path.is_dir():
            for suffix in suffixes:
                files.extend(sorted(path.rglob(f"*{suffix}")))
        elif path.is_file():
            files.append(path)
        else:
            raise SystemExit(f"input not found: {value}")
    return sorted(dict.fromkeys(files))


def first(record: dict[str, Any], *names: str, default: Any = "") -> Any:
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
    return default


def nested(record: dict[str, Any], container: str, *names: str, default: Any = "") -> Any:
    value = record.get(container)
    if isinstance(value, dict):
        return first(value, *names, default=default)
    return default


def event_value(record: dict[str, Any], *names: str, default: Any = "") -> Any:
    value = first(record, *names, default=None)
    if value not in (None, ""):
        return value
    value = nested(record, "process", *names, default=None)
    if value not in (None, ""):
        return value
    value = nested(record, "payload", *names, default=None)
    if value not in (None, ""):
        return value
    return nested(record, "enrich", *names, default=default)


def event_timestamp_ns(record: dict[str, Any]) -> int:
    value = event_value(record, "timestamp_ns", "TimestampNS", "time_ns", default=0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def truth_timestamp_ns(record: dict[str, Any]) -> int:
    value = str(record.get("timestamp") or "")
    if not value:
        return 0
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1_000_000_000)
    except ValueError:
        return 0


def normalize_type(record: dict[str, Any]) -> str:
    event_type = str(event_value(record, "event_type", "type_name", "hook", default="")).lower()
    normalized_type = str(first(record, "type", default="")).lower()
    if normalized_type and not normalized_type.isdigit():
        return normalized_type
    numeric = str(event_value(record, "type", "Type", default="")).strip()
    if event_type:
        return event_type
    return {
        "1": "proc_fork",
        "2": "proc_exec",
        "3": "proc_exit",
        "10": "file_open",
        "11": "file_create",
        "12": "file_modify",
        "13": "file_delete",
        "14": "file_rename",
        "20": "net_connect",
        "21": "net_accept",
        "22": "net_send",
        "23": "net_recv",
        "50": "memfd_create",
        "51": "mprotect_rx",
        "52": "pipe_write",
        "53": "pipe_read",
    }.get(numeric, numeric or "unknown")


def event_command(record: dict[str, Any]) -> str:
    command = str(event_value(record, "command", "cmdline", "args", default="")).strip()
    if command:
        return command
    comm = str(event_value(record, "comm", "Comm", default="")).strip()
    exe = str(event_value(record, "exe_path", "ExePath", "exe", default="")).strip()
    return " ".join(part for part in [exe or comm] if part)


def event_path(record: dict[str, Any]) -> str:
    return str(event_value(record, "pathname", "Pathname", "path", "file_path", default="")).strip()


def event_network(record: dict[str, Any]) -> str:
    dst = str(event_value(record, "daddr", "Daddr", "dst_addr", "remote_addr", default="")).strip()
    port = str(event_value(record, "dport", "Dport", "dst_port", "remote_port", default="")).strip()
    if dst and dst != "0":
        return f"{dst}:{port or 0}"
    return ""


def node_id(kind: str, value: Any) -> str:
    text = str(value).strip() or "unknown"
    return f"{kind}:{text}"


def edge_kind(event_type: str, path: str, network: str) -> str:
    lowered = event_type.lower()
    if "exec" in lowered or "fork" in lowered:
        return "exec"
    if network:
        return "network"
    if path and any(token in lowered for token in ("write", "create", "unlink", "chmod")):
        return "file_write"
    if path:
        return "file_read"
    return "observed"


def quality_summary(events: list[dict[str, Any]], truths: list[dict[str, Any]], matched_truth_count: int, fallback_truth_count: int) -> dict[str, Any]:
    total = len(events)

    def present_count(func: Any) -> int:
        return sum(1 for event in events if str(func(event) or "").strip())

    cmdline_count = present_count(event_command)
    procfs_cmdline_count = sum(1 for event in events if str(event_value(event, "cmdline_source", default="")).strip() == "procfs")
    cwd_count = sum(1 for event in events if str(event_value(event, "cwd", default="")).strip())
    exe_count = sum(1 for event in events if str(event_value(event, "exe_path", "ExePath", default="")).strip())
    paths = [event_path(event) for event in events if event_path(event)]
    absolute_paths = [path for path in paths if path.startswith("/")]
    event_types = Counter(normalize_type(event) for event in events)
    return {
        "event_count": total,
        "ground_truth_count": len(truths),
        "truth_matched_count": matched_truth_count,
        "truth_fallback_count": fallback_truth_count,
        "truth_match_rate_percent": round((matched_truth_count / max(1, len(truths))) * 100.0, 2),
        "cmdline_present_percent": round((cmdline_count / max(1, total)) * 100.0, 2),
        "cmdline_procfs_percent": round((procfs_cmdline_count / max(1, total)) * 100.0, 2),
        "cwd_present_percent": round((cwd_count / max(1, total)) * 100.0, 2),
        "exe_path_present_percent": round((exe_count / max(1, total)) * 100.0, 2),
        "path_present_percent": round((len(paths) / max(1, total)) * 100.0, 2),
        "absolute_path_percent": round((len(absolute_paths) / max(1, len(paths))) * 100.0, 2),
        "event_type_summary": dict(event_types.most_common()),
    }


def normalize_feedback_classification(value: Any) -> str:
    normalized = str(value or "").lower().strip().replace("-", "_").replace(" ", "_")
    if normalized == "tp":
        return "true_positive"
    if normalized == "fp":
        return "false_positive"
    if normalized in {"true_positive", "false_positive", "benign", "duplicate", "needs_review"}:
        return normalized
    return "needs_review"


def feedback_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    by_classification = Counter(normalize_feedback_classification(entry.get("classification")) for entry in entries)
    by_action = Counter(str(entry.get("action") or "unknown").strip() or "unknown" for entry in entries)
    alert_ids = {str(entry.get("alert_id") or "").strip() for entry in entries if str(entry.get("alert_id") or "").strip()}
    reviewed = sum(by_classification[key] for key in ("true_positive", "false_positive", "benign", "duplicate"))
    return {
        "feedback_entry_count": len(entries),
        "feedback_alert_count": len(alert_ids),
        "feedback_reviewed_count": reviewed,
        "feedback_needs_review_count": by_classification["needs_review"],
        "feedback_by_classification": dict(sorted(by_classification.items())),
        "feedback_by_action": dict(sorted(by_action.items())),
    }


def split_for(graph_id: str, seed: str) -> str:
    bucket = int(hashlib.sha256(f"{seed}|{graph_id}".encode("utf-8")).hexdigest()[:8], 16) / 0xFFFFFFFF
    if bucket < 0.70:
        return "train"
    if bucket < 0.85:
        return "val"
    return "test"


def truth_terms(record: dict[str, Any]) -> list[str]:
    fields = [
        "command",
        "actor",
        "object",
        "expected_event",
        "step_name",
        "technique_id",
        "technique_name",
    ]
    return [str(record.get(field, "")).lower() for field in fields if str(record.get(field, "")).strip()]


def matches_truth(event: dict[str, Any], truth: dict[str, Any], window_ns: int) -> bool:
    truth_ns = truth_timestamp_ns(truth)
    event_ns = event_timestamp_ns(event)
    if truth_ns and event_ns and abs(event_ns - truth_ns) > window_ns:
        return False
    haystack = " ".join([
        normalize_type(event),
        event_command(event),
        event_path(event),
        event_network(event),
        str(event_value(event, "comm", "Comm", default="")),
    ]).lower()
    return any(term and term in haystack for term in truth_terms(truth))


def build_graph(events: list[dict[str, Any]], truths: list[dict[str, Any]], graph_id: str, split_seed: str, include_truth_nodes: bool = False) -> dict[str, Any]:
    node_kinds: dict[str, str] = {}
    node_events: Counter[str] = Counter()
    edges: Counter[tuple[str, str, str]] = Counter()
    matched_truth: list[dict[str, Any]] = []

    def add_node(kind: str, value: Any) -> str:
        identifier = node_id(kind, value)
        node_kinds[identifier] = kind
        return identifier

    for event in events:
        pid = event_value(event, "pid", "PID", default="unknown")
        comm = event_value(event, "comm", "Comm", default="")
        process = add_node("process", f"{pid}:{comm or 'unknown'}")
        node_events[process] += 1
        uid = event_value(event, "uid", "UID", default="")
        if uid not in ("", None):
            user = add_node("user", uid)
            edges[(user, process, "user_context")] += 1
        parent = event_value(event, "ppid", "PPID", default="")
        if parent not in ("", None, 0, "0"):
            parent_node = add_node("process", f"{parent}:parent")
            edges[(parent_node, process, "exec")] += 1
        path = event_path(event)
        network = event_network(event)
        kind = edge_kind(normalize_type(event), path, network)
        if network:
            target = add_node("network", network)
            edges[(process, target, kind)] += 1
            node_events[target] += 1
        if path:
            target = add_node("file", path)
            edges[(process, target, kind)] += 1
            node_events[target] += 1

    for truth in truths:
        matched_truth.append(truth)
        if include_truth_nodes:
            truth_node = add_node("truth", truth.get("step_id") or truth.get("step_name") or "unknown")
            actor = truth.get("actor")
            obj = truth.get("object")
            if actor:
                edges[(add_node("process", actor), truth_node, "truth_actor")] += 1
            if obj:
                target_kind = "network" if ":" in str(obj) and "/" not in str(obj) else "file"
                edges[(truth_node, add_node(target_kind, obj), "truth_object")] += 1

    indegree: Counter[str] = Counter()
    outdegree: Counter[str] = Counter()
    for src, dst, _kind in edges:
        outdegree[src] += 1
        indegree[dst] += 1

    nodes = []
    for identifier, kind in sorted(node_kinds.items()):
        feature = [
            1.0 if kind == "process" else 0.0,
            1.0 if kind == "file" else 0.0,
            1.0 if kind == "network" else 0.0,
            1.0 if kind == "user" else 0.0,
            1.0 if kind == "truth" else 0.0,
            float(indegree[identifier]),
            float(outdegree[identifier]),
            float(node_events[identifier]),
        ]
        nodes.append({"id": identifier, "type": kind, "features": feature})

    edge_rows = []
    for (src, dst, kind), count in sorted(edges.items()):
        edge_rows.append({
            "source": src,
            "target": dst,
            "type": kind,
            "features": [
                1.0 if kind in ("exec", "truth_actor") else 0.0,
                1.0 if kind == "file_read" else 0.0,
                1.0 if kind in ("file_write", "truth_object") else 0.0,
                1.0 if kind == "network" else 0.0,
                1.0 if kind == "user_context" else 0.0,
                float(count),
            ],
        })

    malicious = any(bool(item.get("malicious")) for item in matched_truth)
    tactics = sorted({str(item.get("tactic_id") or item.get("tactic") or "") for item in matched_truth if item.get("tactic_id") or item.get("tactic")})
    techniques = sorted({str(item.get("technique_id") or "") for item in matched_truth if item.get("technique_id")})
    time_values = [event_timestamp_ns(event) for event in events if event_timestamp_ns(event)]
    return {
        "schema": SCHEMA,
        "graph_id": graph_id,
        "split": split_for(graph_id, split_seed),
        "label": 1 if malicious else 0,
        "label_name": "malicious" if malicious else "benign",
        "attack_category": ",".join(sorted({str(item.get("category", "")) for item in matched_truth if item.get("category")})) or "benign",
        "tactics": tactics,
        "techniques": techniques,
        "event_count": len(events),
        "time_range": {
            "start_ns": min(time_values) if time_values else 0,
            "end_ns": max(time_values) if time_values else 0,
        },
        "ground_truth_refs": [
            {
                "run_id": item.get("run_id", ""),
                "step_id": item.get("step_id", ""),
                "technique_id": item.get("technique_id", ""),
                "malicious": bool(item.get("malicious")),
            }
            for item in matched_truth
        ],
        "nodes": nodes,
        "edges": edge_rows,
    }


def make_feature_schema() -> dict[str, Any]:
    payload = {
        "schema": FEATURE_SCHEMA,
        "node_features": [{"index": index, "name": name, "type": "float32"} for index, name in enumerate(NODE_FEATURES)],
        "edge_features": [{"index": index, "name": name, "type": "float32"} for index, name in enumerate(EDGE_FEATURES)],
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    payload["sha256"] = digest
    return payload


def build_dataset(event_files: list[Path], truth_files: list[Path], args: argparse.Namespace, normal_event_files: list[Path] | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events = [event for path in event_files for event in load_jsonl(path)]
    normal_events = [event for path in (normal_event_files or []) for event in load_jsonl(path)]
    truths = [truth for path in truth_files for truth in load_jsonl(path)]
    feedback_files = iter_files(getattr(args, "alert_feedback", []) or [], (".ndjson", ".jsonl")) if getattr(args, "alert_feedback", None) else []
    feedback_entries = load_optional_jsonl(feedback_files)
    window_ns = int(args.window_seconds * 1_000_000_000)
    graphs: list[dict[str, Any]] = []
    matched_event_indexes: set[int] = set()
    matched_truth_count = 0
    fallback_truth_count = 0
    for truth_index, truth in enumerate(truths):
        matched = []
        for event_index, event in enumerate(events):
            if matches_truth(event, truth, window_ns):
                matched.append(event)
                matched_event_indexes.add(event_index)
        if not matched:
            fallback_truth_count += 1
            matched = [{
                "Type": 0,
                "TimestampNS": truth_timestamp_ns(truth),
                "PID": "truth",
                "Comm": truth.get("actor", "unknown"),
                "Pathname": truth.get("object", ""),
                "command": truth.get("command", ""),
            }]
        else:
            matched_truth_count += 1
        graph_id = f"truth-{truth.get('run_id', 'run')}-{truth.get('step_id', truth_index)}"
        graphs.append(build_graph(matched, [truth], graph_id, args.split_seed, getattr(args, "include_truth_nodes", False)))

    negative_events = normal_events + [event for index, event in enumerate(events) if index not in matched_event_indexes]
    max_negative = max(1, int(len(graphs) * args.negative_ratio)) if graphs else len(negative_events)
    if negative_events:
        chunks: list[list[dict[str, Any]]] = []
        chunk_size = max(1, min(args.normal_window_events, len(negative_events)))
        for offset in range(0, min(len(negative_events), max_negative * chunk_size), chunk_size):
            chunks.append(negative_events[offset:offset + chunk_size])
        for index, chunk in enumerate(chunks[:max_negative]):
            graphs.append(build_graph(chunk, [], f"benign-{index:04d}", args.split_seed, getattr(args, "include_truth_nodes", False)))

    counts = Counter(graph["label_name"] for graph in graphs)
    split_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for graph in graphs:
        split_counts[graph["split"]][graph["label_name"]] += 1
        split_counts[graph["split"]]["total"] += 1
    feature_schema = make_feature_schema()
    manifest = {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "dataset_version": args.dataset_version,
        "dataset_id": "graphds-" + hashlib.sha256(json.dumps(graphs, sort_keys=True).encode("utf-8")).hexdigest()[:16],
        "record_count": len(graphs),
        "event_source_count": len(events) + len(normal_events),
        "attack_event_source_count": len(events),
        "normal_event_source_count": len(normal_events),
        "ground_truth_count": len(truths),
        "label_summary": dict(counts),
        "split_summary": {key: dict(value) for key, value in sorted(split_counts.items())},
        "quality": quality_summary(events + normal_events, truths, matched_truth_count, fallback_truth_count),
        "alert_feedback": feedback_summary(feedback_entries),
        "feature_schema_sha256": feature_schema["sha256"],
        "source_files": [str(path) for path in event_files + (normal_event_files or []) + truth_files + feedback_files],
    }
    return graphs, {"manifest": manifest, "feature_schema": feature_schema}


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build graph-level ML training data from ProvidAPT events and ATT&CK ground truth.")
    parser.add_argument("--events", nargs="+", required=True, help="NDJSON event files or directories")
    parser.add_argument("--normal-events", nargs="*", default=[], help="Benign NDJSON event files or directories used only as negative training windows")
    parser.add_argument("--ground-truth", nargs="+", required=True, help="Ground-truth JSONL files or directories")
    parser.add_argument("--alert-feedback", nargs="*", default=[], help="Optional alert-feedback.ndjson files or directories for dataset provenance")
    parser.add_argument("--out-dir", default="build/ml-dataset")
    parser.add_argument("--dataset-version", default="dev")
    parser.add_argument("--window-seconds", type=float, default=300.0)
    parser.add_argument("--negative-ratio", type=float, default=1.0)
    parser.add_argument("--normal-window-events", type=int, default=64)
    parser.add_argument("--split-seed", default="providapt")
    parser.add_argument("--include-truth-nodes", action="store_true", help="Include ground-truth helper nodes for visualization datasets; keep disabled for model training")
    args = parser.parse_args()

    event_files = iter_files(args.events, (".ndjson", ".jsonl"))
    normal_event_files = iter_files(args.normal_events, (".ndjson", ".jsonl")) if args.normal_events else []
    truth_files = iter_files(args.ground_truth, (".jsonl", ".ndjson"))
    if not event_files:
        raise SystemExit("no event files found")
    if not truth_files:
        raise SystemExit("no ground-truth files found")
    graphs, metadata = build_dataset(event_files, truth_files, args, normal_event_files)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(out_dir / "graphs.jsonl", graphs)
    (out_dir / "manifest.json").write_text(json.dumps(metadata["manifest"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "feature_schema.json").write_text(json.dumps(metadata["feature_schema"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"graphs={len(graphs)} events={metadata['manifest']['event_source_count']} out={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
