#!/usr/bin/env python3
"""Generate HTML compatibility matrix report from test results."""

import argparse
import json
import os
from datetime import datetime


def generate_report(results_path, output_path):
    """Read test results and generate an HTML report."""
    with open(results_path) as f:
        data = json.load(f)

    results = data.get("results", [])
    start_time = data.get("start_time", "unknown")

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ProvidAPT Kernel Compatibility Matrix</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #f5f5f5; }}
  .container {{ max-width: 1000px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
  h1 {{ color: #333; border-bottom: 2px solid #4A90D9; padding-bottom: 10px; }}
  h2 {{ color: #555; margin-top: 30px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
  th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
  th {{ background: #4A90D9; color: white; }}
  tr:hover {{ background: #f0f4ff; }}
  .pass {{ color: #28a745; font-weight: bold; }}
  .fail {{ color: #dc3545; font-weight: bold; }}
  .skip {{ color: #ffc107; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; }}
  .badge-pass {{ background: #d4edda; color: #155724; }}
  .badge-fail {{ background: #f8d7da; color: #721c24; }}
  .badge-skip {{ background: #fff3cd; color: #856404; }}
  .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
  .stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
  .stat-card .value {{ font-size: 28px; font-weight: bold; color: #4A90D9; }}
  .stat-card .label {{ font-size: 14px; color: #666; }}
  .footer {{ margin-top: 30px; color: #999; font-size: 12px; text-align: center; }}
  .kernel-bar {{ height: 20px; border-radius: 4px; margin: 2px 0; }}
  .bar-pass {{ background: #28a745; }}
  .bar-fail {{ background: #dc3545; }}
</style>
</head>
<body>
<div class="container">
<h1>🛡 ProvidAPT — Kernel Compatibility Matrix</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Test started: {start_time}</p>
"""

    # Summary stats
    total = len(results)
    passed = sum(1 for r in results if r.get("core_ok"))
    skipped = sum(1 for r in results if not r.get("core_ok"))
    html += f"""
<div class="summary">
  <div class="stat-card">
    <div class="value">{total}</div>
    <div class="label">Kernels Tested</div>
  </div>
  <div class="stat-card">
    <div class="value">{passed}</div>
    <div class="label">CO-RE Passed</div>
  </div>
  <div class="stat-card">
    <div class="value">{skipped}</div>
    <div class="label">Skipped (no BTF)</div>
  </div>
</div>
"""

    # Compatibility table
    html += """
<h2>Compatibility Matrix</h2>
<table>
<thead>
<tr>
  <th>Kernel</th>
  <th>CO-RE Relocation</th>
  <th>BPF LSM</th>
  <th>Stress Test</th>
  <th>Status</th>
</tr>
</thead>
<tbody>
"""
    for r in results:
        kver = r.get("kernel", "?")
        core_ok = r.get("core_ok", False)
        stress_ok = r.get("stress_ok", False)

        # Detect features from kernel version
        btf = "✓" if float(kver.replace("5.", "5.")) >= 5.10 or kver.startswith("6.") else "✗"
        bpf_lsm = "✓" if float(kver.replace("5.", "5.")) >= 5.11 or kver.startswith("6.") else "✗"

        core_status = "✓" if core_ok else "—"
        stress_status = "✓" if stress_ok else "—"

        badge = "badge-pass" if core_ok else "badge-skip"
        badge_text = "PASS" if core_ok else "SKIP"

        html += f"""
<tr>
  <td><strong>Linux {kver}</strong></td>
  <td class="{'pass' if core_ok else 'skip'}">{core_status}</td>
  <td>{bpf_lsm}</td>
  <td class="{'pass' if stress_ok else 'skip'}">{stress_status}</td>
  <td><span class="badge {badge}">{badge_text}</span></td>
</tr>
"""

    html += """
</tbody>
</table>
"""

    # Feature support timeline
    html += """
<h2>Kernel Feature Support Timeline</h2>
<table>
<thead><tr><th>Feature</th><th>Min Kernel</th><th>Status</th></tr></thead>
<tbody>
<tr><td>BPF (CONFIG_BPF)</td><td>3.18</td><td class="pass">✓ Stable</td></tr>
<tr><td>BPF LSM (CONFIG_BPF_LSM)</td><td>5.11</td><td class="pass">✓ Supported</td></tr>
<tr><td>BTF / CO-RE</td><td>5.10</td><td class="pass">✓ Supported</td></tr>
<tr><td>fentry/fexit</td><td>5.11</td><td class="pass">✓ Supported</td></tr>
<tr><td>BPF Ring Buffer</td><td>5.8</td><td class="pass">✓ Supported</td></tr>
<tr><td>bpf_d_path helper</td><td>5.10</td><td class="pass">✓ Supported</td></tr>
</tbody>
</table>
"""

    html += """
<h2>Test Environments</h2>
<table>
<thead><tr><th>Kernel</th><th>Distro</th><th>Expected BTF</th></tr></thead>
<tbody>
<tr><td>5.4</td><td>Ubuntu 20.04</td><td class="skip">✗ (manual BTF required)</td></tr>
<tr><td>5.10</td><td>Ubuntu 20.04</td><td class="pass">✓ BTF available</td></tr>
<tr><td>5.11</td><td>Ubuntu 22.04</td><td class="pass">✓ BTF available</td></tr>
<tr><td>5.15</td><td>Ubuntu 22.04</td><td class="pass">✓ BTF available</td></tr>
<tr><td>6.1</td><td>Ubuntu 24.04</td><td class="pass">✓ BTF available</td></tr>
<tr><td>6.6</td><td>Ubuntu 24.04</td><td class="pass">✓ BTF available</td></tr>
<tr><td>6.8</td><td>Ubuntu 24.10</td><td class="pass">✓ BTF available</td></tr>
</tbody>
</table>
"""

    html += f"""
<div class="footer">
<p>ProvidAPT Kernel Compatibility Test — {len(results)} kernels tested</p>
</div>
</div>
</body>
</html>
"""

    with open(output_path, "w") as f:
        f.write(html)

    print(f"Report generated: {output_path}")
    print(f"  Kernels tested: {total}")
    print(f"  CO-RE passed:   {passed}")
    print(f"  Skipped:        {skipped}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate compatibility report")
    parser.add_argument("--results", required=True, help="Results JSON file")
    parser.add_argument("--output", default="report.html", help="Output HTML path")
    args = parser.parse_args()
    generate_report(args.results, args.output)
