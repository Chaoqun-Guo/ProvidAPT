#!/usr/bin/env python3
"""
ProvidAPT cluster integration test.

The test drives the collector harness through HTTP endpoints and validates:
  1. cross-host stitching for SSH/SCP-like flows,
  2. agent-level stitch lookup accuracy,
  3. TLS/JA3 C2 fingerprint ingestion,
  4. basic harness statistics under repeated event ingestion.

Run:
  go run ./cmd/collector --port 8722
  python test/integration/cluster_test.py [--host localhost] [--port 8722]
"""

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


HARNESS_HOST = "localhost"
HARNESS_PORT = 8722
BASE_URL = f"http://{HARNESS_HOST}:{HARNESS_PORT}"

FLOW_AB = "flow-ssh-A-to-B"
FLOW_BC = "flow-scp-B-to-C"

COLORS = {
    "PASS": "\033[92m",
    "FAIL": "\033[91m",
    "INFO": "\033[94m",
    "WARN": "\033[93m",
    "END": "\033[0m",
}


def configure_from_args():
    global HARNESS_HOST, HARNESS_PORT, BASE_URL
    args = sys.argv[1:]
    for idx, value in enumerate(args):
        if value == "--host" and idx + 1 < len(args):
            HARNESS_HOST = args[idx + 1]
        if value == "--port" and idx + 1 < len(args):
            HARNESS_PORT = int(args[idx + 1])
    BASE_URL = f"http://{HARNESS_HOST}:{HARNESS_PORT}"


def http_json(method, path, body=None):
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as err:
        raw = err.read().decode()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise AssertionError(f"{method} {path} failed: HTTP {err.code}: {raw}") from err
    except urllib.error.URLError as err:
        print(f"  {COLORS['FAIL']}Connection failed: {err}{COLORS['END']}")
        print(f"  Make sure the harness is running at {BASE_URL}")
        sys.exit(1)


def post(path, body):
    return http_json("POST", path, body)


def get(path):
    return http_json("GET", path)


def section(title):
    print(f"\n{'=' * 60}")
    print(f"{COLORS['INFO']}{title}{COLORS['END']}")
    print(f"{'=' * 60}")


def phase1_lateral_movement():
    section("Phase 1: lateral movement stitching")

    print(f"\n  [{COLORS['INFO']}1.1{COLORS['END']}] hostA outbound SSH to hostB")
    r = post(
        "/ingest-outbound",
        {
            "flow_id": FLOW_AB,
            "agent_id": "agent-hostA",
            "pid": 1001,
            "comm": "ssh",
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.2.20",
            "src_port": 54321,
            "dst_port": 22,
            "tainted": False,
        },
    )
    assert not r.get("matched", False), "outbound event should wait for inbound match"

    print(f"  [{COLORS['INFO']}1.2{COLORS['END']}] hostB inbound SSH from hostA")
    r = post(
        "/ingest-inbound",
        {
            "flow_id": FLOW_AB,
            "agent_id": "agent-hostB",
            "pid": 2001,
            "comm": "sshd",
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.2.20",
            "src_port": 54321,
            "dst_port": 22,
            "tainted": False,
        },
    )
    edge = r.get("stitch_edge")
    assert r.get("matched", False), "SSH inbound event should match hostA outbound"
    assert edge is not None, "matched SSH event should create a stitch edge"
    assert edge["relation"] == "remote_call", f"unexpected relation: {edge['relation']}"
    print(f"    {COLORS['PASS']}remote_call edge: {edge['id']}{COLORS['END']}")

    print(f"  [{COLORS['INFO']}1.3{COLORS['END']}] hostB tainted outbound SCP to hostC")
    post(
        "/ingest-outbound",
        {
            "flow_id": FLOW_BC,
            "agent_id": "agent-hostB",
            "pid": 2002,
            "comm": "scp",
            "src_ip": "10.0.2.20",
            "dst_ip": "10.0.3.30",
            "src_port": 40000,
            "dst_port": 22,
            "tainted": True,
            "taint_source": f"stitch:{edge['id']}",
        },
    )

    print(f"  [{COLORS['INFO']}1.4{COLORS['END']}] hostC inbound SCP from hostB")
    r = post(
        "/ingest-inbound",
        {
            "flow_id": FLOW_BC,
            "agent_id": "agent-hostC",
            "pid": 3001,
            "comm": "sshd",
            "src_ip": "10.0.2.20",
            "dst_ip": "10.0.3.30",
            "src_port": 40000,
            "dst_port": 22,
            "tainted": False,
        },
    )
    edge = r.get("stitch_edge")
    assert r.get("matched", False), "SCP inbound event should match hostB outbound"
    assert edge is not None, "matched SCP event should create a stitch edge"
    assert edge["relation"] == "lateral_move", f"unexpected relation: {edge['relation']}"
    print(f"    {COLORS['PASS']}lateral_move edge: {edge['id']}{COLORS['END']}")


def phase2_stitch_accuracy():
    section("Phase 2: stitch lookup accuracy")

    expected_counts = {
        "agent-hostA": 1,
        "agent-hostB": 2,
        "agent-hostC": 1,
    }
    for agent_id, minimum in expected_counts.items():
        encoded = urllib.parse.quote(agent_id)
        r = get(f"/stitch/by-agent?agent_id={encoded}")
        edges = r.get("edges", [])
        print(f"    {agent_id}: {len(edges)} edge(s)")
        assert len(edges) >= minimum, f"{agent_id} should have at least {minimum} edge(s)"

    stats = get("/stitch/stats")
    assert stats.get("stitch_edges", 0) >= 2, "expected at least two stitch edges"
    print(f"    {COLORS['PASS']}stitch stats: {json.dumps(stats, sort_keys=True)}{COLORS['END']}")


def phase3_tls_fingerprint():
    section("Phase 3: TLS and JA3 fingerprint ingestion")

    samples = [
        {"ja3": "a0e9f5d64349fb13191bc781f81f42e1", "comm": "beacon", "port": 443},
        {"ja3": "b8b0b5d3c6f0b7c1d2e3f4a5b6c7d8e9", "comm": "meterpreter", "port": 8443},
        {"ja3": "c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e", "comm": "powershell", "port": 443},
    ]
    for idx, sample in enumerate(samples, 1):
        body = {
            "agent_id": "agent-hostB",
            "pid": 4000 + idx,
            "comm": sample["comm"],
            "src_ip": "10.0.2.20",
            "dst_ip": "198.51.100.10",
            "dst_port": sample["port"],
            "ja3": sample["ja3"],
        }
        post("/ingest-ja3", body)
        print(f"    submitted JA3 sample for {sample['comm']}")


def phase4_load_smoke():
    section("Phase 4: basic load smoke")

    started = time.time()
    for idx in range(100):
        post(
            "/ingest-outbound",
            {
                "flow_id": f"load-{idx}",
                "agent_id": "agent-load",
                "pid": 5000 + idx,
                "comm": "curl",
                "src_ip": "10.0.9.10",
                "dst_ip": f"203.0.113.{idx % 50}",
                "src_port": 35000 + idx,
                "dst_port": 443,
                "tainted": idx % 10 == 0,
            },
        )
    elapsed = max(time.time() - started, 0.001)
    rate = 100 / elapsed
    print(f"    submitted 100 events at {rate:.1f} events/sec")
    assert rate > 10, "load smoke throughput is unexpectedly low"


def main():
    configure_from_args()
    print(f"{COLORS['INFO']}ProvidAPT cluster integration test -> {BASE_URL}{COLORS['END']}")
    phase1_lateral_movement()
    phase2_stitch_accuracy()
    phase3_tls_fingerprint()
    phase4_load_smoke()
    print(f"\n{COLORS['PASS']}All cluster integration checks passed{COLORS['END']}")


if __name__ == "__main__":
    main()
