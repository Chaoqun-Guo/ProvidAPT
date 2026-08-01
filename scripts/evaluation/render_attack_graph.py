#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


PALETTE = {
    "pre-compromise": "#6D5DF6",
    "compromise": "#EF7B45",
    "post-compromise": "#D94C8A",
    "movement": "#2F80ED",
    "collection": "#00A88F",
    "c2": "#9B51E0",
    "exfiltration": "#EB5757",
    "impact": "#B7791F",
    "benign": "#5F6C7B",
}


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
                item.setdefault("_source_file", str(path))
                rows.append(item)
    return rows


def iter_inputs(values: list[str]) -> list[Path]:
    files: list[Path] = []
    for value in values:
        path = Path(value)
        if path.is_dir():
            files.extend(sorted(path.rglob("ground_truth*.jsonl")))
        elif path.is_file():
            files.append(path)
        else:
            raise SystemExit(f"input not found: {value}")
    if not files:
        raise SystemExit("no ground-truth files found")
    return sorted(dict.fromkeys(files))


def short_text(value: Any, limit: int = 64) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def host_label(run_id: str) -> str:
    if "ubuntu" in run_id:
        return "ubuntu agent"
    if "localhost.localdomain" in run_id or "centos" in run_id:
        return "centos agent"
    return run_id or "unknown host"


def group_by_run(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("run_id") or "unknown")].append(row)
    for run_rows in grouped.values():
        run_rows.sort(key=lambda item: (int(item.get("step_index") or 0), str(item.get("step_id") or "")))
    return dict(sorted(grouped.items()))


def render_svg(rows: list[dict[str, Any]], title: str) -> str:
    grouped = group_by_run(rows)
    lane_gap = 760
    card_width = 560
    card_height = 106
    card_gap = 38
    margin_x = 70
    margin_y = 92
    max_steps = max((len(items) for items in grouped.values()), default=1)
    width = margin_x * 2 + max(1, len(grouped)) * lane_gap - (lane_gap - card_width)
    height = margin_y + max_steps * (card_height + card_gap) + 90

    svg: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">',
        "<defs>",
        '<marker id="arrow" markerWidth="14" markerHeight="10" refX="12" refY="5" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L14,5 L0,10 z" fill="#273447"/></marker>',
        '<filter id="shadow" x="-10%" y="-10%" width="120%" height="130%"><feDropShadow dx="0" dy="4" stdDeviation="5" flood-color="#1f2937" flood-opacity="0.18"/></filter>',
        "</defs>",
        '<rect width="100%" height="100%" rx="22" fill="#F7F9FC"/>',
        f'<text x="{margin_x}" y="42" font-family="Inter, Segoe UI, Arial" font-size="24" font-weight="800" fill="#172033">{html.escape(title)}</text>',
        f'<text x="{margin_x}" y="67" font-family="Inter, Segoe UI, Arial" font-size="13" fill="#5F6C7B">Directed ATT&amp;CK chain: actor → step → object, grouped by VM run. Colors indicate attack phase.</text>',
    ]

    legend_x = width - 560
    legend_y = 34
    for index, (name, color) in enumerate(PALETTE.items()):
        x = legend_x + (index % 5) * 108
        y = legend_y + (index // 5) * 22
        svg.append(f'<rect x="{x}" y="{y}" width="12" height="12" rx="3" fill="{color}"/>')
        svg.append(f'<text x="{x + 18}" y="{y + 11}" font-family="Inter, Segoe UI, Arial" font-size="11" fill="#4A5568">{html.escape(name)}</text>')

    for lane_index, (run_id, run_rows) in enumerate(grouped.items()):
        x = margin_x + lane_index * lane_gap
        svg.append(f'<text x="{x}" y="{margin_y - 16}" font-family="Inter, Segoe UI, Arial" font-size="16" font-weight="800" fill="#172033">{html.escape(host_label(run_id))}</text>')
        previous_center = None
        for row_index, row in enumerate(run_rows):
            y = margin_y + row_index * (card_height + card_gap)
            center_x = x + card_width / 2
            center_y = y + card_height / 2
            if previous_center:
                svg.append(
                    f'<path d="M {previous_center[0]} {previous_center[1] + card_height / 2 - 8} '
                    f'C {previous_center[0]} {previous_center[1] + card_height / 2 + 28}, {center_x} {center_y - card_height / 2 - 28}, {center_x} {center_y - card_height / 2 + 4}" '
                    'fill="none" stroke="#273447" stroke-width="2.2" marker-end="url(#arrow)" opacity="0.65"/>'
                )
            previous_center = (center_x, center_y)

            category = str(row.get("category") or "benign")
            color = PALETTE.get(category, "#5F6C7B")
            label = f"{row.get('step_id', '')} · {row.get('step_name', '')}"
            tactic = f"{row.get('tactic_id', '')} {row.get('tactic_name', '')}"
            technique = f"{row.get('technique_id', '')} {row.get('technique_name', '')}"
            actor = short_text(row.get("actor"), 28)
            obj = short_text(row.get("object"), 48)
            command = short_text(row.get("command"), 76)
            svg.extend([
                f'<rect x="{x}" y="{y}" width="{card_width}" height="{card_height}" rx="16" fill="#FFFFFF" stroke="{color}" stroke-width="2.5" filter="url(#shadow)"/>',
                f'<rect x="{x}" y="{y}" width="12" height="{card_height}" rx="6" fill="{color}"/>',
                f'<text x="{x + 24}" y="{y + 24}" font-family="Inter, Segoe UI, Arial" font-size="15" font-weight="800" fill="#172033">{html.escape(short_text(label, 70))}</text>',
                f'<text x="{x + 24}" y="{y + 46}" font-family="Inter, Segoe UI, Arial" font-size="12" font-weight="700" fill="{color}">{html.escape(short_text(tactic, 76))}</text>',
                f'<text x="{x + 24}" y="{y + 64}" font-family="Inter, Segoe UI, Arial" font-size="12" fill="#344054">{html.escape(short_text(technique, 80))}</text>',
                f'<text x="{x + 24}" y="{y + 84}" font-family="Inter, Segoe UI, Arial" font-size="11" fill="#5F6C7B">actor: {html.escape(actor)} → object: {html.escape(obj)}</text>',
                f'<text x="{x + 24}" y="{y + 100}" font-family="Inter, Segoe UI, Arial" font-size="10" fill="#667085">cmd: {html.escape(command)}</text>',
            ])
    svg.append("</svg>")
    return "\n".join(svg)


def render_html(svg: str, rows: list[dict[str, Any]], title: str) -> str:
    table_rows = []
    for row in sorted(rows, key=lambda item: (str(item.get("run_id") or ""), int(item.get("step_index") or 0))):
        table_rows.append(
            "<tr>"
            f"<td>{html.escape(host_label(str(row.get('run_id') or '')))}</td>"
            f"<td>{html.escape(str(row.get('step_id') or ''))}</td>"
            f"<td>{html.escape(str(row.get('category') or ''))}</td>"
            f"<td>{html.escape(str(row.get('tactic_id') or ''))}</td>"
            f"<td>{html.escape(str(row.get('technique_id') or ''))}</td>"
            f"<td>{html.escape(str(row.get('step_name') or ''))}</td>"
            f"<td>{html.escape(short_text(row.get('command'), 120))}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
  <style>
    body {{ margin: 0; padding: 24px; background: #eef2f7; color: #172033; font-family: Inter, Segoe UI, Arial, sans-serif; }}
    .canvas {{ overflow: auto; border: 1px solid #d7dee9; border-radius: 20px; background: white; box-shadow: 0 10px 30px rgba(15,23,42,.08); }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 22px; background: white; border-radius: 14px; overflow: hidden; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #edf1f7; text-align: left; font-size: 12px; vertical-align: top; }}
    th {{ background: #172033; color: white; position: sticky; top: 0; }}
  </style>
</head>
<body>
  <div class="canvas">{svg}</div>
  <table>
    <thead><tr><th>Host</th><th>Step</th><th>Category</th><th>Tactic</th><th>Technique</th><th>Name</th><th>Command</th></tr></thead>
    <tbody>{''.join(table_rows)}</tbody>
  </table>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a directed ATT&CK ground-truth graph as SVG/HTML.")
    parser.add_argument("inputs", nargs="+", help="Ground-truth JSONL files or directories")
    parser.add_argument("--out-svg", default="build/ml-readiness-vm-data/attack-graph.svg")
    parser.add_argument("--out-html", default="build/ml-readiness-vm-data/attack-graph.html")
    parser.add_argument("--title", default="ProvidAPT Full-Chain Attack Graph")
    args = parser.parse_args()
    rows = [row for path in iter_inputs(args.inputs) for row in load_jsonl(path)]
    svg = render_svg(rows, args.title)
    out_svg = Path(args.out_svg)
    out_html = Path(args.out_html)
    out_svg.parent.mkdir(parents=True, exist_ok=True)
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_svg.write_text(svg + "\n", encoding="utf-8")
    out_html.write_text(render_html(svg, rows, args.title), encoding="utf-8")
    print(f"rendered steps={len(rows)} svg={out_svg} html={out_html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
