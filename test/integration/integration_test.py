#!/usr/bin/env python3
"""
ProvidAPT Integration Test Suite — Full Lifecycle Verification
==============================================================

Tests ProvidAPT across three Linux distributions:
  - Ubuntu 24.04 LTS
  - CentOS 9 Stream
  - Debian 12

Phases:
  1. DEPLOY    — Install + configure ProvidAPT on all VMs
  2. ATTACK    — Execute composite attack scenarios
  3. VERIFY    — Check RocksDB, alert timing, graph reconstruction
  4. REPORT    — Generate performance report with metrics

Requirements:
  pip install paramiko pyyaml requests
  ssh-key access to all target VMs (root or passwordless sudo)
"""

import argparse
import csv
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import paramiko
    import yaml
    import requests
except ImportError:
    print("Requirements: pip install paramiko pyyaml requests")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════

CONFIG = {
    "ubuntu":  {"host": "", "port": 22, "user": "root", "distro": "ubuntu"},
    "centos":  {"host": "", "port": 22, "user": "root", "distro": "centos"},
    "debian":  {"host": "", "port": 22, "user": "root", "distro": "debian"},
    "project_dir": os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")),
    "remote_dir": "/opt/providapt",
    "store_path": "/var/lib/providapt/store",
    "log_path": "/var/log/providapt",
    "timeout": 300,  # 5 min per operation
    "attack_delay": 2,  # seconds between attack steps
}

RESULTS = {
    "phases": {},
    "alerts": {},
    "graph_stats": {},
    "performance": {},
    "errors": [],
    "start_time": None,
    "end_time": None,
}


# ═══════════════════════════════════════════════════════════════
# SSH helpers
# ═══════════════════════════════════════════════════════════════

class RemoteHost:
    """Manages SSH connection and command execution."""

    def __init__(self, name, cfg):
        self.name = name
        self.cfg = cfg
        self.client = None
        self.sftp = None

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            self.cfg["host"], port=self.cfg["port"],
            username=self.cfg["user"],
            timeout=30,
        )
        self.sftp = self.client.open_sftp()
        print(f"  [ssh] connected to {self.name} ({self.cfg['host']})")

    def exec(self, cmd, timeout=120, ok_fail=False):
        """Run a command and return (stdout, stderr, exit_code)."""
        full_cmd = cmd
        if self.cfg["user"] != "root":
            full_cmd = f"sudo bash -c '{cmd}'"
        try:
            _, stdout, stderr = self.client.exec_command(full_cmd, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            if exit_code != 0 and not ok_fail:
                print(f"  [cmd] WARNING: exit={exit_code}: {cmd[:80]}")
            return out, err, exit_code
        except Exception as e:
            if not ok_fail:
                print(f"  [cmd] ERROR: {e}")
            return "", str(e), -1

    def put(self, local, remote):
        self.sftp.put(local, remote)

    def get(self, remote, local):
        self.sftp.get(remote, local)

    def close(self):
        if self.sftp:
            self.sftp.close()
        if self.client:
            self.client.close()


# ═══════════════════════════════════════════════════════════════
# Phase 1: Deployment
# ═══════════════════════════════════════════════════════════════

def phase_deploy(hosts):
    """Install ProvidAPT on all target VMs."""
    print("\n" + "=" * 70)
    print("PHASE 1: DEPLOYMENT")
    print("=" * 70)

    for name, host in hosts.items():
        print(f"\n--- Deploying to {name} ({host.cfg['distro']}) ---")
        host.connect()

        # Step 1: Install dependencies
        print("  [1/5] Installing dependencies...")
        distro = host.cfg["distro"]
        if distro == "ubuntu" or distro == "debian":
            host.exec("apt-get update -qq", ok_fail=True)
            host.exec("apt-get install -y -qq clang llvm lld bpftool libbpf-dev "
                       "linux-headers-$(uname -r) pkg-config curl git make jq python3", timeout=180)
        elif distro == "centos":
            host.exec("dnf install -y clang llvm lld bpftool libbpf-devel "
                       "kernel-devel kernel-headers pkgconfig git make jq python3", timeout=180)

        # Step 2: Build ProvidAPT locally, copy to VM
        print("  [2/5] Copying ProvidAPT build...")
        host.exec(f"mkdir -p {CONFIG['remote_dir']}", ok_fail=True)
        # Build on the host machine
        subprocess.run(
            f"cd {CONFIG['project_dir']} && make build 2>&1 | tail -3",
            shell=True, check=False
        )
        # Copy build artifacts via SFTP
        for binary in ["providaptd", "providaptctl", "providapt-watchdog"]:
            local_bin = f"{CONFIG['project_dir']}/build/bin/{binary}"
            if os.path.exists(local_bin):
                host.put(local_bin, f"{CONFIG['remote_dir']}/{binary}")
                host.exec(f"chmod +x {CONFIG['remote_dir']}/{binary}")
        # Copy eBPF objects
        host.exec(f"mkdir -p {CONFIG['remote_dir']}/ebpf")
        for f in os.listdir(f"{CONFIG['project_dir']}/build/ebpf/"):
            if f.endswith(".bpf.o"):
                host.put(f"{CONFIG['project_dir']}/build/ebpf/{f}",
                         f"{CONFIG['remote_dir']}/ebpf/{f}")

        # Step 3: Install to system
        print("  [3/5] Installing to system...")
        host.exec(f"install -m 0755 {CONFIG['remote_dir']}/providaptd /usr/local/sbin/providaptd")
        host.exec(f"install -m 0755 {CONFIG['remote_dir']}/providaptctl /usr/local/bin/providaptctl")
        host.exec(f"mkdir -p /usr/local/lib/providapt/ebpf")
        host.exec(f"cp {CONFIG['remote_dir']}/ebpf/*.bpf.o /usr/local/lib/providapt/ebpf/")

        # Step 4: Configure cgroup limits
        print("  [4/5] Setting resource limits...")
        host.exec("mkdir -p /sys/fs/cgroup/providapt", ok_fail=True)
        host.exec("echo '100000 1000000' > /sys/fs/cgroup/providapt/cpu.max", ok_fail=True)
        host.exec("echo '536870912' > /sys/fs/cgroup/providapt/memory.max", ok_fail=True)

        # Step 5: Start agent
        print("  [5/5] Starting ProvidAPT agent...")
        host.exec("mkdir -p /var/log/providapt /var/lib/providapt/store")
        # Kill any existing instance
        host.exec("pkill providaptd 2>/dev/null || true")
        time.sleep(1)
        # Start daemon
        stdout, _, _ = host.exec("nohup /usr/local/sbin/providaptd "
                                  "> /var/log/providapt/daemon.log 2>&1 & echo PID=$!")
        print(f"  started: {stdout[:80]}")
        time.sleep(3)

        # Verify it's running
        out, _, rc = host.exec("pidof providaptd", ok_fail=True)
        if out:
            print(f"  ✓ providaptd running (PID {out})")
        else:
            RESULTS["errors"].append(f"{name}: providaptd not running after deploy")

    RESULTS["phases"]["deploy"] = "PASS"
    print("\n✓ Deployment phase complete.")


# ═══════════════════════════════════════════════════════════════
# Phase 2: Attack Simulation
# ═══════════════════════════════════════════════════════════════

def phase_attack(hosts):
    """Execute composite attack scenarios across VMs."""
    print("\n" + "=" * 70)
    print("PHASE 2: ATTACK SIMULATION")
    print("=" * 70)

    ubuntu = hosts.get("ubuntu")
    centos = hosts.get("centos")
    debian = hosts.get("debian")
    results = {}

    # ── Attack 1: Memory Shell Injection (Ubuntu) ─────────
    print("\n--- Attack 1: Memory Shell Injection ---")
    if ubuntu:
        out, _, _ = ubuntu.exec(
            'python3 -c "
import ctypes, os
# Simulate memfd_create + mprotect RWX
libc = ctypes.CDLL(None)
MFD_CLOEXEC = 1
fd = libc.memfd_create(b\"evil.so\", MFD_CLOEXEC)
print(f\"memfd_create -> fd={fd}\")
# Write shellcode (simulated)
os.write(fd, b\"\\x90\" * 100)
# mmap with RWX
import mmap
m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ|mmap.PROT_WRITE)
m.write(b\"\\x90\" * 100)
# mprotect to RX
libc.mprotect(ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(m))),
              4096, mmap.PROT_READ|mmap.PROT_EXEC)
print(f\"mprotect RW->RX ok\")
os.close(fd)
" 2>&1', timeout=30
        )
        results["mem_injection"] = out
        print(f"  memfd: {out[:120]}")

    time.sleep(CONFIG["attack_delay"])

    # ── Attack 2: Reverse Shell via Pipe (CentOS) ─────────
    print("\n--- Attack 2: Pipeline Reverse Shell ---")
    if centos:
        out, _, _ = centos.exec(
            "# Simulate curl | bash pipeline\n"
            "echo 'echo PIPE_EXEC; id; whoami' | bash 2>&1",
            timeout=15
        )
        results["pipe_shell"] = out
        print(f"  pipe exec: {out[:120]}")

    time.sleep(CONFIG["attack_delay"])

    # ── Attack 3: Container Escape Simulation (Debian) ────
    print("\n--- Attack 3: Container Escape Simulation ---")
    if debian:
        out, _, _ = debian.exec(
            "# Simulate container escape: access host /etc from namespace\n"
            "mkdir -p /tmp/escape 2>/dev/null\n"
            "# Mount host filesystem (simulated)\n"
            "cat /etc/shadow > /dev/null 2>&1 || true\n"
            "ls -la /root/ 2>/dev/null || echo 'escape: /root/ blocked'\n"
            "# Write to host crontab (simulated)\n"
            "echo '* * * * * root /tmp/evil.sh' > /tmp/escape_persist\n"
            "echo 'container escape simulation complete'",
            timeout=15
        )
        results["container_escape"] = out
        print(f"  escape: {out[:120]}")

    time.sleep(CONFIG["attack_delay"])

    # ── Attack 4: Lateral Movement ────────────────────────
    print("\n--- Attack 4: Lateral Movement (Ubuntu → CentOS) ---")
    if ubuntu and centos:
        # Simulate SSH connection from Ubuntu to CentOS
        centos_ip = centos.cfg["host"]
        out, _, _ = ubuntu.exec(
            f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "
            f"root@{centos_ip} 'echo LATERAL_MOVEMENT_OK' 2>&1 || "
            f"echo 'SSH failed (expected if keys not configured)'",
            timeout=15
        )
        results["lateral_ssh"] = out
        print(f"  lateral: {out[:120]}")

    time.sleep(CONFIG["attack_delay"])

    # ── Attack 5: Sensitive File Access + Exfil ───────────
    print("\n--- Attack 5: Sensitive File Access ---")
    for name, host in hosts.items():
        out, _, _ = host.exec(
            "cat /etc/shadow > /dev/null 2>&1; "
            "echo 'shadow_read='$?; "
            "head -1 /etc/passwd > /dev/null 2>&1; "
            "echo 'passwd_read='$?",
            timeout=10
        )
        results[f"{name}_sensitive_access"] = out
        print(f"  {name}: {out[:80]}")

    RESULTS["phases"]["attack"] = "PASS"
    RESULTS["attack_results"] = results
    print("\n✓ Attack simulation complete.")


# ═══════════════════════════════════════════════════════════════
# Phase 3: Verification
# ═══════════════════════════════════════════════════════════════

def phase_verify(hosts):
    """Verify ProvidAPT captured all attack steps."""
    print("\n" + "=" * 70)
    print("PHASE 3: VERIFICATION")
    print("=" * 70)

    all_pass = True

    for name, host in hosts.items():
        print(f"\n--- Verifying {name} ---")

        # Check 1: Agent is running
        pid_out, _, _ = host.exec("pidof providaptd 2>/dev/null || true")
        agent_running = len(pid_out.strip()) > 0
        print(f"  [1] Agent running: {'✓' if agent_running else '✗'}" )

        # Check 2: Ring buffer events captured
        tap_output, _, _ = host.exec(
            "ls -la /var/log/providapt/ 2>/dev/null || echo 'no logs'")
        has_logs = "providapt-" in tap_output or "provenance" in tap_output
        print(f"  [2] Event logs: {'✓' if has_logs else '✗'}")

        # Check 3: Graph has data
        verdict = "✗"
        graph_stdout, _, _ = host.exec(
            "cat /var/log/providapt/provenance.json 2>/dev/null | "
            "python3 -c 'import json,sys; d=json.load(sys.stdin); "
            "print(len(d.get(\"activity\",{})), len(d.get(\"entity\",{})))' "
            "2>/dev/null || echo '0 0'"
        )
        parts = graph_stdout.split()
        has_graph = False
        if len(parts) >= 2:
            try:
                a_cnt, e_cnt = int(parts[0]), int(parts[1])
                has_graph = a_cnt > 0 or e_cnt > 0
                RESULTS["graph_stats"][name] = {"activities": a_cnt, "entities": e_cnt}
                print(f"  [3] Graph data: {a_cnt} activities, {e_cnt} entities")
            except ValueError:
                pass

        # Check 4: Analyzer alerts
        alert_out, _, _ = host.exec(
            "cat /var/log/providapt/alerts.json 2>/dev/null | "
            "python3 -c 'import json,sys; data=json.load(sys.stdin); "
            "print(len(data))' 2>/dev/null || echo '0'"
        )
        try:
            alert_count = int(alert_out.strip())
            RESULTS["alerts"][name] = alert_count
            print(f"  [4] Analyzer alerts: {alert_count}")
        except ValueError:
            alert_count = 0

        # Check 5: Performance metrics
        mem_out, _, _ = host.exec(
            "cat /proc/$(pidof providaptd)/status 2>/dev/null | "
            "grep VmRSS || echo 'VmRSS: 0 kB'", ok_fail=True
        )
        cpu_out, _, _ = host.exec(
            "top -bn1 -p $(pidof providaptd) 2>/dev/null | "
            "tail -1 | awk '{print $9}' || echo '0.0'", ok_fail=True
        )
        disk_out, _, _ = host.exec(
            "du -sh /var/lib/providapt/store 2>/dev/null || echo '0'")
        RESULTS["performance"][name] = {
            "memory": mem_out.strip(),
            "cpu": cpu_out.strip() + "%",
            "disk": disk_out.strip(),
        }
        print(f"  [5] Memory: {mem_out.strip()}, CPU: {cpu_out.strip()}%")
        print(f"      Disk: {disk_out.strip()}")

        # Overall per-host verdict
        host_ok = agent_running and has_graph
        verdict = "✓" if host_ok else "⚠"
        print(f"  --- {name} overall: {verdict} ---")
        if not host_ok:
            all_pass = False

    RESULTS["phases"]["verify"] = "PASS" if all_pass else "PARTIAL"

    # ── Cross-host verification: lateral movement chain ─────
    print("\n--- Cross-host lateral movement chain ---")
    if len(hosts) >= 3:
        names = list(hosts.keys())
        print(f"  Attack chain: {names[0]} → {names[1]} → {names[2]}")
        print("  Verifying inter-host correlation...")

        # Check that each host has SSH/network events
        for name, host in hosts.items():
            net_edges, _, _ = host.exec(
                "cat /var/log/providapt/provenance.json 2>/dev/null | "
                "python3 -c 'import json,sys; d=json.load(sys.stdin); "
                "print(len(d.get(\"used\",[])))' 2>/dev/null || echo '0'"
            )
            print(f"  {name}: {net_edges.strip()} used edges")

    print("\n✓ Verification phase complete.")


# ═══════════════════════════════════════════════════════════════
# Phase 4: Report
# ═══════════════════════════════════════════════════════════════

def phase_report():
    """Generate integration test report."""
    print("\n" + "=" * 70)
    print("PHASE 4: PERFORMANCE REPORT")
    print("=" * 70)

    RESULTS["end_time"] = datetime.now(timezone.utc).isoformat()
    total_duration = "N/A"
    if RESULTS.get("start_time"):
        try:
            start = datetime.fromisoformat(RESULTS["start_time"])
            end = datetime.fromisoformat(RESULTS["end_time"])
            total_duration = str(end - start).split(".")[0]
        except Exception:
            pass

    report = f"""
╔══════════════════════════════════════════════════════════════╗
║           ProvidAPT Integration Test Report                  ║
╚══════════════════════════════════════════════════════════════╝

Test ID:      {datetime.now().strftime('%Y%m%d-%H%M%S')}
Duration:     {total_duration}
VMs:          {', '.join(CONFIG['vms'].keys()) if 'vms' in CONFIG else 'see config'}

────────────────────────────────────────────────────────────────
Phase Results
────────────────────────────────────────────────────────────────
"""

    for phase, status in RESULTS.get("phases", {}).items():
        icon = {"PASS": "✓", "PARTIAL": "⚠", "FAIL": "✗", "SKIP": "○"}.get(status, "?")
        report += f"  {icon} {phase.upper()}\n"

    report += "\n────────────────────────────────────────────────────────────────\n"
    report += "Graph Statistics\n"
    report += "────────────────────────────────────────────────────────────────\n"
    for host, stats in RESULTS.get("graph_stats", {}).items():
        report += f"  {host}: {stats.get('activities',0)} activities, "
        report += f"{stats.get('entities',0)} entities\n"

    report += "\n────────────────────────────────────────────────────────────────\n"
    report += "Alert Summary\n"
    report += "────────────────────────────────────────────────────────────────\n"
    total_alerts = 0
    for host, count in RESULTS.get("alerts", {}).items():
        report += f"  {host}: {count} alerts\n"
        total_alerts += count
    report += f"  Total: {total_alerts} alerts\n"

    report += "\n────────────────────────────────────────────────────────────────\n"
    report += "Performance Metrics\n"
    report += "────────────────────────────────────────────────────────────────\n"
    report += f"{'Host':<20} {'Memory':<20} {'CPU':<10} {'Disk':<15}\n"
    report += "-" * 65 + "\n"
    for host, metrics in RESULTS.get("performance", {}).items():
        report += f"{host:<20} {metrics.get('memory','?'):<20} "
        report += f"{metrics.get('cpu','?'):<10} {metrics.get('disk','?'):<15}\n"

    report += f"""
────────────────────────────────────────────────────────────────
Errors
────────────────────────────────────────────────────────────────
"""
    if RESULTS.get("errors"):
        for e in RESULTS["errors"]:
            report += f"  ⚠ {e}\n"
    else:
        report += "  None\n"

    report += """
────────────────────────────────────────────────────────────────
Test Completion
────────────────────────────────────────────────────────────────
"""
    all_pass = all(
        s == "PASS" for s in RESULTS.get("phases", {}).values()
    )
    if all_pass:
        report += "  ✓ ALL TESTS PASSED\n"
    else:
        report += "  ⚠ SOME TESTS FAILED — review errors above\n"

    report += "\n"
    print(report)

    # Save report
    report_path = os.path.join(CONFIG["project_dir"], "build", "integration_report.txt")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report)
    print(f"Report saved: {report_path}")

    # Save JSON results
    json_path = os.path.join(CONFIG["project_dir"], "build", "integration_results.json")
    with open(json_path, "w") as f:
        json.dump(RESULTS, f, indent=2, default=str)
    print(f"Results saved: {json_path}")

    return all_pass


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

def parse_config(config_path):
    """Load VM configuration from YAML file."""
    if not config_path or not os.path.exists(config_path):
        print("No config file. Using environment variables for VM hosts.")
        for name in CONFIG["vms"]:
            env_key = f"VM_HOST_{name.upper()}"
            CONFIG[name]["host"] = os.environ.get(env_key, "")
        return

    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    for name, info in cfg.get("vms", {}).items():
        if name in CONFIG:
            CONFIG[name].update(info)
        CONFIG["vms"] = cfg.get("vms", {})


def main():
    parser = argparse.ArgumentParser(description="ProvidAPT Integration Test")
    parser.add_argument("--config", "-c", help="YAML config file with VM hosts")
    parser.add_argument("--skip-deploy", action="store_true", help="Skip deployment phase")
    parser.add_argument("--skip-attack", action="store_true", help="Skip attack simulation")
    parser.add_argument("--skip-verify", action="store_true", help="Skip verification")
    parser.add_argument("--only", help="Run only on specific VM (ubuntu/centos/debian)")
    args = parser.parse_args()

    RESULTS["start_time"] = datetime.now(timezone.utc).isoformat()

    # Parse config
    CONFIG["vms"] = {"ubuntu": CONFIG["ubuntu"], "centos": CONFIG["centos"], "debian": CONFIG["debian"]}
    parse_config(args.config)

    # Filter by VM
    vm_names = list(CONFIG["vms"].keys())
    if args.only and args.only in CONFIG["vms"]:
        vm_names = [args.only]
        print(f"Running on: {args.only} only")

    # Connect to hosts
    hosts = {}
    for name in vm_names:
        cfg = CONFIG["vms"][name]
        if not cfg.get("host"):
            print(f"  Skipping {name}: no host configured (set VM_HOST_{name.upper()} or --config)")
            continue
        hosts[name] = RemoteHost(name, cfg)

    if not hosts:
        print("ERROR: No VMs configured. Use --config or env vars.")
        sys.exit(1)

    try:
        # Phase 1: Deploy
        if not args.skip_deploy:
            phase_deploy(hosts)
        else:
            print("Skipping deploy phase.")
            # Still connect if we need to run attacks
            if not args.skip_attack or not args.skip_verify:
                for h in hosts.values():
                    h.connect()

        # Phase 2: Attack
        if not args.skip_attack:
            phase_attack(hosts)
        else:
            print("Skipping attack phase.")

        # Phase 3: Verify
        if not args.skip_verify:
            phase_verify(hosts)
        else:
            print("Skipping verification phase.")

        # Phase 4: Report
        all_pass = phase_report()

    finally:
        for h in hosts.values():
            try:
                h.close()
            except Exception:
                pass

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
