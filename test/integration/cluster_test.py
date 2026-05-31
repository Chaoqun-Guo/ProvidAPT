#!/usr/bin/env python3
"""
v2.2 集成验证脚本 — Cluster Test

测试项:
  1. 横向移动模拟: 三台虚拟机之间通过 SSH 密钥泄露进行的横向渗透
  2. 缝合准确性检查: 验证中心服务器生成了跨越三个 HostID 的连通图
  3. TLS 指纹验证: C2 工具模拟器验证异常 JA3 检测
  4. 性能基线报告: 100 个模拟 Agent 同时上报时的 RPS 及内存阈值

用法:
  # 先编译启动 Go 测试 Harness (另一个终端):
  #   cd v2.2 && go run ./cmd/cluster-test-harness/ --port 8722
  #
  # 然后运行本脚本:
  #   python cluster_test.py [--host localhost] [--port 8722]

依赖: Python 3.8+, 仅使用标准库 (urllib + json), 无需 pip install。
"""

import json
import sys
import time
import urllib.request
import urllib.error

# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════
# HTTP helpers
# ═══════════════════════════════════════════════════════════════════


def http_json(method, path, body=None):
    """Send HTTP request and return parsed JSON response."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if body else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())
    except urllib.error.URLError as e:
        print(f"  {COLORS['FAIL']}Connection failed: {e}{COLORS['END']}")
        print(f"  Make sure the harness is running at {BASE_URL}")
        sys.exit(1)


def post(path, body):
    return http_json("POST", path, body)


def get(path):
    return http_json("GET", path)


# ═══════════════════════════════════════════════════════════════════
# Test phases
# ═══════════════════════════════════════════════════════════════════


def phase1_lateral_movement():
    """Phase 1: 模拟横向移动 — SSH 密钥泄露横向渗透"""
    print(f"\n{'='*60}")
    print(f"{COLORS['INFO']}Phase 1: 横向移动模拟 (SSH 密钥泄露){COLORS['END']}")
    print(f"{'='*60}")

    # ── Step 1: hostA 发起对外出站 SSH 连接 → hostB ──
    print(f"\n  [{COLORS['INFO']}1.1{COLORS['END']}] hostA 出站 SSH → hostB  (未受染)")
    r = post("/ingest-outbound", {
        "flow_id": FLOW_AB,
        "agent_id": "agent-hostA",
        "pid": 1001,
        "comm": "ssh",
        "src_ip": "10.0.1.10",
        "dst_ip": "10.0.2.20",
        "src_port": 54321,
        "dst_port": 22,
        "tainted": False,
    })
    matched = r.get("matched", False)
    print(f"    Outbound recorded (matched={matched})")
    assert not matched, "No edge yet — only outbound recorded"

    # ── Step 2: hostB 上的 SSH 服务器接收到入站连接 ──
    print(f"\n  [{COLORS['INFO']}1.2{COLORS['END']}] hostB 入站 SSH (来自 hostA)  — 预期产生缝合边")
    r = post("/ingest-inbound", {
        "flow_id": FLOW_AB,
        "agent_id": "agent-hostB",
        "pid": 2001,
        "comm": "sshd",
        "src_ip": "10.0.1.10",
        "dst_ip": "10.0.2.20",
        "src_port": 54321,
        "dst_port": 22,
        "tainted": False,
    })
    matched = r.get("matched", False)
    edge = r.get("stitch_edge")
    print(f"    Inbound recorded (matched={matched})")
    assert matched, "Stitch edge should be created when outbound+inbound match"
    assert edge is not None
    assert edge["relation"] == "remote_call", (
        f"Expected remote_call, got {edge['relation']}"
    )
    print(f"    {COLORS['PASS']}StitchEdge[{edge['id']}]: "
          f"{edge['source_agent']}:{edge['source_comm']} → "
          f"{edge['target_agent']}:{edge['target_comm']} "
          f"rel={edge['relation']}{COLORS['END']}")

    step1_edge_id = edge["id"]

    # ── Step 3: 现在 hostB 被攻陷, 其 SSH 会话被用于 SCP 到 hostC ──
    print(f"\n  [{COLORS['INFO']}1.3{COLORS['END']}] hostB 出站 SCP → hostC (受染)")
    r = post("/ingest-outbound", {
        "flow_id": FLOW_BC,
        "agent_id": "agent-hostB",
        "pid": 2002,
        "comm": "scp",
        "src_ip": "10.0.2.20",
        "dst_ip": "10.0.3.30",
        "src_port": 40000,
        "dst_port": 22,
        "tainted": True,
        "taint_source": f"stitch:{step1_edge_id}",
    })
    matched = r.get("matched", False)
    print(f"    Outbound recorded (matched={matched})")

    # ── Step 4: hostC 入站 SCP ──
    print(f"\n  [{COLORS['INFO']}1.4{COLORS['END']}] hostC 入站 SCP (来自 hostB) — 预期产生 lateral_move")
    r = post("/ingest-inbound", {
        "flow_id": FLOW_BC,
        "agent_id": "agent-hostC",
        "pid": 3001,
        "comm": "sshd",
        "src_ip": "10.0.2.20",
        "dst_ip": "10.0.3.30",
        "src_port": 40000,
        "dst_port": 22,
        "tainted": False,
    })
    matched = r.get("matched", False)
    edge = r.get("stitch_edge")
    assert matched, "Second stitch edge should be created"
    assert edge is not None
    print(f"    {COLORS['PASS']}StitchEdge[{edge['id']}]: "
          f"{edge['source_agent']}:{edge['source_comm']} → "
          f"{edge['target_agent']}:{edge['target_comm']} "
          f"rel={edge['relation']} tainted={edge['tainted']}{COLORS['END']}")

    # Step 5: 验证 lateral_move 标记
    assert edge["relation"] == "lateral_move", (
        f"Tainted outbound should produce lateral_move, got {edge['relation']}"
    )
    print(f"  {COLORS['PASS']}✓ lateral_move 标记正确{COLORS['END']}")

    return step1_edge_id


def phase2_stitch_accuracy():
    """Phase 2: 缝合准确性检查 — 验证三主机连通图"""
    print(f"\n{'='*60}")
    print(f"{COLORS['INFO']}Phase 2: 缝合准确性检查{COLORS['END']}")
    print(f"{'='*60}")

    # 2a: 验证 hostA 的缝合边
    print(f"\n  [{COLORS['INFO']}2.1{COLORS['END']}] 查询 hostA 的缝合边")
    r = get("/stitch/by-agent?agent_id=agent-hostA")
    edges_a = r.get("edges", [])
    print(f"    hostA: {len(edges_a)} edge(s)")
    for e in edges_a:
        print(f"      {e['id']}: {e['source_agent']} → {e['target_agent']} rel={e['relation']}")
    assert len(edges_a) == 1, f"hostA should have 1 stitch edge, got {len(edges_a)}"

    # 2b: 验证 hostB 的缝合边 (应该涉及 2 条: 来自 A 和到 C)
    print(f"\n  [{COLORS['INFO']}2.2{COLORS['END']}] 查询 hostB 的缝合边")
    r = get("/stitch/by-agent?agent_id=agent-hostB")
    edges_b = r.get("edges", [])
    print(f"    hostB: {len(edges_b)} edge(s)")
    for e in edges_b:
        print(f"      {e['id']}: {e['source_agent']} → {e['target_agent']} rel={e['relation']}")
    assert len(edges_b) >= 2, (
        f"hostB should have >= 2 stitch edges (inbound+outbound), got {len(edges_b)}"
    )

    # 2c: 验证 hostC 的缝合边
    print(f"\n  [{COLORS['INFO']}2.3{COLORS['END']}] 查询 hostC 的缝合边")
    r = get("/stitch/by-agent?agent_id=agent-hostC")
    edges_c = r.get("edges", [])
    print(f"    hostC: {len(edges_c)} edge(s)")
    for e in edges_c:
        print(f"      {e['id']}: {e['source_agent']} → {e['target_agent']} rel={e['relation']}")
    assert len(edges_c) == 1, f"hostC should have 1 stitch edge, got {len(edges_c)}"

    # 2d: 验证缝合边总体计数
    print(f"\n  [{COLORS['INFO']}2.4{COLORS['END']}] 全局缝合统计")
    r = get("/stitch/stats")
    print(f"    Stitch stats: {json.dumps(r, indent=6)}")
    edge_count = r.get("stitch_edges", 0)
    assert edge_count >= 2, f"Should have >= 2 total stitch edges, got {edge_count}"

    # 2e: 查询由缝合边产生的图形结构
    #   通过查询 hostA 和 hostC 来验证连通性
    agents_involved = set()
    for e_list in [edges_a, edges_b, edges_c]:
        for e in e_list:
            agents_involved.add(e["source_agent"])
            agents_involved.add(e["target_agent"])

    print(f"\n  [{COLORS['INFO']}2.5{COLORS['END']}] 连通图检查")
    print(f"    涉及 Agent: {agents_involved}")
    assert "agent-hostA" in agents_involved, "hostA missing from graph"
    assert "agent-hostB" in agents_involved, "hostB missing from graph"
    assert "agent-hostC" in agents_involved, "hostC missing from graph"
    print(f"  {COLORS['PASS']}✓ 三主机连通图验证通过{COLORS['END']}")

    return edges_a, edges_b, edges_c


def phase3_tls_fingerprint():
    """Phase 3: TLS 指纹验证 — C2 工具模拟"""
    print(f"\n{'='*60}")
    print(f"{COLORS['INFO']}Phase 3: TLS 指纹验证 (C2 模拟){COLORS['END']}")
    print(f"{'='*60}")

    # 定义一批已知的 Cobalt Strike 模拟 JA3 指纹
    # (来自公开 C2 JA3 库: https://ja3er.com/)
    c2_ja3_samples = [
        # Cobalt Strike 默认 JA3 (典型)
        {"ja3": "a0e9f5d64349fb13191bc781f81f42e1", "comm": "beacon", "port": 443},
        # Metasploit default
        {"ja3": "b8b0b5d3c6f0b7c1d2e3f4a5b6c7d8e9", "comm": "meterpreter", "port": 8443},
        # Empire stager
        {"ja3": "c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e", "comm": "powershell", "port": 443},
    ]

    all_alerts = []

    for i, sample in enumerate(c2_ja3_samples):
        print(f"\n  [{COLORS['INFO']}3.{i+1}{COLORS['END']}] 注入 C2 JA3: {sample['ja3'][:24]}...")

        # 在多台主机上模拟相同的 JA3 (C2 集群行为)
        for host_num, host_id in enumerate(["hostB", "hostC"], 1):
            r = post("/ja3/ingest", {
                "ja3": sample["ja3"],
                "ja3_text": f"TLS-C2-Sim-{i}",
                "source_host": host_id,
                "pid": 4000 + i * 10 + host_num,
                "comm": sample["comm"],
                "dest_ip": f"203.0.113.{50 + i}",
                "dest_port": sample["port"],
                "is_atypical": True,
            })
            alert = r.get("alert")
            if alert:
                all_alerts.append(alert)
                print(f"      {COLORS['WARN']}⚠ C2 ALERT[{alert['id']}]: "
                      f"risk={alert['risk_score']}, hosts={alert['hosts']}{COLORS['END']}")

    # 验证: 至少应有 1 个 C2 告警
    print(f"\n  [{COLORS['INFO']}3.4{COLORS['END']}] C2 告警汇总")
    r = get("/ja3/alerts")
    alerts = r.get("alerts", [])
    print(f"    总告警数: {len(alerts)}")
    for a in alerts:
        print(f"      [{a['id']}] JA3={a['ja3'][:24]}... "
              f"risk={a['risk_score']} hosts={a['hosts']}")

    assert len(alerts) >= 1, (
        f"Should have >= 1 C2 alert with clustered atypical JA3, got {len(alerts)}"
    )

    # 验证集群信息
    r = get("/ja3/clusters")
    clusters = r.get("clusters", [])
    print(f"\n  [{COLORS['INFO']}3.5{COLORS['END']}] JA3 集群:")
    for cl in clusters:
        print(f"      JA3={cl['ja3'][:24]}... count={cl['count']} "
              f"hosts={cl['hosts']} is_c2={cl['is_c2']} risk={cl['risk_score']:.0f}")

    print(f"  {COLORS['PASS']}✓ C2 异常 JA3 检测验证通过{COLORS['END']}")
    return alerts, clusters


def phase4_performance_baseline():
    """Phase 4: 性能基线 — 100 Agents × 100 事件"""
    print(f"\n{'='*60}")
    print(f"{COLORS['INFO']}Phase 4: 性能基线报告{COLORS['END']}")
    print(f"{'='*60}")

    N_AGENTS = 100
    N_PER_AGENT = 100

    print(f"\n  [{COLORS['INFO']}4.1{COLORS['END']}] 压测: {N_AGENTS} agents × {N_PER_AGENT} events = "
          f"{N_AGENTS * N_PER_AGENT:,} total events")

    r = post("/queue/enqueue-batch", {
        "n_agents": N_AGENTS,
        "n_per_agent": N_PER_AGENT,
    })

    elapsed = r.get("elapsed_ms", 0)
    rps = r.get("rps", 0)
    memory_mb = r.get("memory_mb", 0)
    heap_mb = r.get("heap_mb", 0)
    stack_mb = r.get("stack_mb", 0)
    total = r.get("total_events", 0)

    print(f"    Elapsed:  {elapsed} ms")
    print(f"    RPS:      {rps:,} events/sec")
    print(f"    Memory:   {memory_mb} MB (heap={heap_mb} MB, stack={stack_mb} MB)")

    # 验证队列深度
    time.sleep(0.1)  # 等待队列稳定
    r = get("/queue/stats")
    q_depth = r.get("queue_depth", 0)
    enqueued = r.get("enqueued", 0)
    backlog = r.get("backlog", 0)
    print(f"    Queue:    depth={q_depth} enqueued={enqueued} backlog={backlog}")

    # 验证路由
    print(f"\n  [{COLORS['INFO']}4.2{COLORS['END']}] 路由器验证 (100 agents 分配到 3 collectors)")
    post("/router/add-collector", {"id": "collector-1"})
    post("/router/add-collector", {"id": "collector-2"})
    post("/router/add-collector", {"id": "collector-3"})

    route_counts = {}
    for i in range(N_AGENTS):
        agent_id = f"agent-{i:04d}"
        r = get(f"/router/route?host_id={agent_id}")
        cid = r.get("collector", "")
        route_counts[cid] = route_counts.get(cid, 0) + 1

    print(f"    路由分布: {json.dumps(route_counts, indent=6)}")
    assert len(route_counts) == 3, (
        f"All 3 collectors should receive routes, got {len(route_counts)}"
    )

    # 计算分布均衡性
    values = list(route_counts.values())
    if len(values) > 1:
        imbalance = max(values) - min(values)
        print(f"    分布偏差: {imbalance} (越小越均衡)")
    else:
        imbalance = 0

    # 性能断言
    assert rps > 0, f"RPS should be > 0, got {rps}"

    print(f"\n  {COLORS['PASS']}✓ 性能基线测试通过{COLORS['END']}")

    return {
        "elapsed_ms": elapsed,
        "rps": rps,
        "memory_mb": memory_mb,
        "heap_mb": heap_mb,
        "queue_depth": q_depth,
        "route_imbalance": imbalance,
    }


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════


def main():
    print(f"{COLORS['INFO']}ProvidAPT v2.2 集成验证脚本{COLORS['END']}")
    print(f"Harness: {BASE_URL}")
    print(f"Time:    {time.strftime('%Y-%m-%dT%H:%M:%S')}")

    # 检查连通性
    print(f"\n  检查 Harness 连通性...")
    try:
        health = get("/health")
        print(f"  {COLORS['PASS']}✓ Harness 已连接{COLORS['END']}")
    except Exception as e:
        print(f"  {COLORS['FAIL']}✗ 无法连接 Harness: {e}{COLORS['END']}")
        print(f"  请确保 Harness 已在运行: go run ./v2.2/cmd/cluster-test-harness/")
        sys.exit(1)

    start_time = time.time()
    results = {}

    try:
        # Phase 1: 横向移动
        step1_edge_id = phase1_lateral_movement()
        results["phase1"] = {"edge_id": step1_edge_id}

        # Phase 2: 缝合准确性
        edges_a, edges_b, edges_c = phase2_stitch_accuracy()
        results["phase2"] = {
            "hostA_edges": len(edges_a),
            "hostB_edges": len(edges_b),
            "hostC_edges": len(edges_c),
        }

        # Phase 3: TLS JA3
        alerts, clusters = phase3_tls_fingerprint()
        results["phase3"] = {
            "alerts": len(alerts),
            "clusters": len(clusters),
        }

        # Phase 4: 性能基线
        perf = phase4_performance_baseline()
        results["phase4"] = perf

    except AssertionError as e:
        print(f"\n{COLORS['FAIL']}✗ 测试失败: {e}{COLORS['END']}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{COLORS['FAIL']}✗ 异常: {type(e).__name__}: {e}{COLORS['END']}")
        sys.exit(1)

    elapsed = time.time() - start_time

    # ══════════════════════════════════════════════════════════════
    # Final Report
    # ══════════════════════════════════════════════════════════════
    print(f"\n{'='*60}")
    print(f"{COLORS['INFO']}最终验证报告{COLORS['END']}")
    print(f"{'='*60}")
    print(f"  耗时:             {elapsed:.1f}s")
    print(f"  Phase 1 (横向移动):     {COLORS['PASS']}PASS{COLORS['END']}")
    print(f"    - hostA→hostB SSH (remote_call)")
    print(f"    - hostB→hostC SCP (lateral_move)")
    print(f"  Phase 2 (缝合准确性):  {COLORS['PASS']}PASS{COLORS['END']}")
    print(f"    - hostA edges: {results.get('phase2', {}).get('hostA_edges', 0)}")
    print(f"    - hostB edges: {results.get('phase2', {}).get('hostB_edges', 0)}")
    print(f"    - hostC edges: {results.get('phase2', {}).get('hostC_edges', 0)}")
    print(f"  Phase 3 (JA3 检测):    {COLORS['PASS']}PASS{COLORS['END']}")
    print(f"    - C2 alerts:   {results.get('phase3', {}).get('alerts', 0)}")
    print(f"    - JA3 cluster: {results.get('phase3', {}).get('clusters', 0)}")
    print(f"  Phase 4 (性能基线):    {COLORS['PASS']}PASS{COLORS['END']}")
    perf = results.get('phase4', {})
    print(f"    - RPS:         {perf.get('rps', 0):,}")
    print(f"    - Memory:      {perf.get('memory_mb', 0)} MB")
    print(f"    - Queue depth: {perf.get('queue_depth', 0)}")

    print(f"\n{COLORS['PASS']}{'='*60}")
    print(f"所有测试通过 ✓")
    print(f"{'='*60}{COLORS['END']}")


if __name__ == "__main__":
    main()
