#!/usr/bin/env python3
"""
ProvidAPT 闂傚棗妫欓崹姘殽瀹€鍐闁煎瓨纰嶅﹢-闁-Cluster Test

婵炴潙顑堥惁顖涖亜-
  1. 婵☆垼浜滈幃婊呯矓鐠囨彃袟婵☆垪鍓濈€- 濞戞挸顦ぐ鎾惞濮橆厼鐝柡鍫ｆ〃缁狅綁姊婚幘顔瑰亾濮樺磭绠-SSH 閻庨潧妫濋幐婊冣枖閸曨垱鑻熼弶鈺傜椤㈡垿鎯冮崟顑烆參宕ラ幋鐐电懖闂-  2. 缂傚倹绻傞幃搴ㄥ礄閸℃瑢鈧﹢骞€瑜庨ˉ鍛村蓟- 濡ょ姴鐭侀惁澶嬬▔椤撶偟濡囬柡鍫濈Т婵喖宕抽妸褎鏅搁柟瀛樺姃缁紕鎹勯妸銊ㄥ☉鎾愁槷闁-HostID 闁汇劌瀚换娑㈡焻濮橆剚绂-  3. TLS 闁圭娲ㄥЧ妤侇殽瀹€鍐: C2 鐎规悶鍎遍崣鍨熼埄鍐ㄧ彲闁革絻鍔戦悰娆戞嫚娴ｅ摜纾介悽-JA3 婵☆偀鍋撴繛-  4. 闁诡儸鍡楀幋闁糕晞娅ｉ崵搴ㄥ箮閵夈儲鍟- 100 濞戞搩浜濊啯闁-Agent 闁告艾鏈鍌涚▔婵犲啫袚闁哄啫澧庡▓-RPS 闁告瑥锕ら崬瀵糕偓娑欙耿濡插洭宕-
闁活潿鍔嶇涵-
  # 闁稿繐鐗忕槐顏嗘嫚閹存繃鍎欓柛-Go 婵炴潙顑堥惁-Harness (闁告瑱缂氱粩瀛樼▔椤忓棛鐭掔紒-:
  #   go run ./cmd/collector --port 8722
  #
  # 闁绘帟娉涢幃妤佹交閹邦垼鏀介柡鍫墲閸撳ジ寮-
  #   python cluster_test.py [--host localhost] [--port 8722]

濞撴碍绻嗙粋- Python 3.8+, 濞寸姴鎳嶆繛鍥偨閵婏妇鍨奸柛鎴濇缁-(urllib + json), 闁哄啰濞€濞-pip install闁-"""

import json
import sys
import time
import urllib.request
import urllib.error

# 闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛-# Configuration
# 闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛-
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

# 闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛-# HTTP helpers
# 闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛-

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


# 闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛-# Test phases
# 闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛-

def phase1_lateral_movement():
    """Phase 1: 婵☆垪鍓濈€氭瑥螣椤忓嫭鍊荤紒澶庮嚙婵-闁-SSH 閻庨潧妫濋幐婊冣枖閸曨垱鑻熸俊顖ｄ簻閹粌銆掑Δ鍛亾-""
    print(f"\n{'='*60}")
    print(f"{COLORS['INFO']}Phase 1: 婵☆垼浜滈幃婊呯矓鐠囨彃袟婵☆垪鍓濈€-(SSH 閻庨潧妫濋幐婊冣枖閸曨垱鑻-{COLORS['END']}")
    print(f"{'='*60}")

    # 闁冲厜鍋撻柍鍏夊亾 Step 1: hostA 闁告瑦鍨奸幑锝団偓鐢垫嚀椤﹀宕欓搹鍦讲 SSH 閺夆晝鍋炵敮-闁-hostB 闁冲厜鍋撻柍鍏夊亾
    print(f"\n  [{COLORS['INFO']}1.1{COLORS['END']}] hostA 闁告垼娅ｉ悵-SSH 闁-hostB  (闁哄牜浜滆ぐ鍫ュ蓟-")
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
    assert not matched, "No edge yet 闁-only outbound recorded"

    # 闁冲厜鍋撻柍鍏夊亾 Step 2: hostB 濞戞挸锕﹀▓-SSH 闁哄牆绉存慨鐔煎闯閵婏箑澶嶉柡鈧捄鍝勭厒闁稿繈鍎抽悵顖涙交閻愭潙澶-闁冲厜鍋撻柍鍏夊亾
    print(f"\n  [{COLORS['INFO']}1.2{COLORS['END']}] hostB 闁稿繈鍎抽悵-SSH (闁哄鍎撮崵-hostA)  闁-濡澘瀚﹢鈩冪瑜忛弫鎾剁磽濠靛棙鍊ら弶-)
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
          f"{edge['source_agent']}:{edge['source_comm']} 闁-"
          f"{edge['target_agent']}:{edge['target_comm']} "
          f"rel={edge['relation']}{COLORS['END']}")

    step1_edge_id = edge["id"]

    # 闁冲厜鍋撻柍鍏夊亾 Step 3: 闁绘粍婢樺﹢-hostB 閻炴凹鍋呴弫楣冩⒔- 闁-SSH 濞村吋淇洪惁鐣屾偖椤愩倖鏆忓ù-SCP 闁-hostC 闁冲厜鍋撻柍鍏夊亾
    print(f"\n  [{COLORS['INFO']}1.3{COLORS['END']}] hostB 闁告垼娅ｉ悵-SCP 闁-hostC (闁告瑦顨嗛悡-")
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

    # 闁冲厜鍋撻柍鍏夊亾 Step 4: hostC 闁稿繈鍎抽悵-SCP 闁冲厜鍋撻柍鍏夊亾
    print(f"\n  [{COLORS['INFO']}1.4{COLORS['END']}] hostC 闁稿繈鍎抽悵-SCP (闁哄鍎撮崵-hostB) 闁-濡澘瀚﹢鈩冪瑜忛弫-lateral_move")
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
          f"{edge['source_agent']}:{edge['source_comm']} 闁-"
          f"{edge['target_agent']}:{edge['target_comm']} "
          f"rel={edge['relation']} tainted={edge['tainted']}{COLORS['END']}")

    # Step 5: 濡ょ姴鐭侀惁-lateral_move 闁哄秴娲╅-    assert edge["relation"] == "lateral_move", (
        f"Tainted outbound should produce lateral_move, got {edge['relation']}"
    )
    print(f"  {COLORS['PASS']}闁-lateral_move 闁哄秴娲╅鍥ь潰閿濆洠鈧COLORS['END']}")

    return step1_edge_id


def phase2_stitch_accuracy():
    """Phase 2: 缂傚倹绻傞幃搴ㄥ礄閸℃瑢鈧﹢骞€瑜庨ˉ鍛村蓟-闁-濡ょ姴鐭侀惁澶嬬▔婢跺鐦滈柡鍫ョ細缁绘盯鏌呭顒佺"""
    print(f"\n{'='*60}")
    print(f"{COLORS['INFO']}Phase 2: 缂傚倹绻傞幃搴ㄥ礄閸℃瑢鈧﹢骞€瑜庨ˉ鍛村蓟椤ㄤ竼OLORS['END']}")
    print(f"{'='*60}")

    # 2a: 濡ょ姴鐭侀惁-hostA 闁汇劌瀚槐鎶藉触閸絿鐝-    print(f"\n  [{COLORS['INFO']}2.1{COLORS['END']}] 闁哄被鍎撮-hostA 闁汇劌瀚槐鎶藉触閸絿鐝-)
    r = get("/stitch/by-agent-agent_id=agent-hostA")
    edges_a = r.get("edges", [])
    print(f"    hostA: {len(edges_a)} edge(s)")
    for e in edges_a:
        print(f"      {e['id']}: {e['source_agent']} 闁-{e['target_agent']} rel={e['relation']}")
    assert len(edges_a) == 1, f"hostA should have 1 stitch edge, got {len(edges_a)}"

    # 2b: 濡ょ姴鐭侀惁-hostB 闁汇劌瀚槐鎶藉触閸絿鐝-(閹煎瓨妫侀姘槈婢跺﹤鎸-2 闁- 闁哄鍎撮崵-A 闁告粌鑻崺-C)
    print(f"\n  [{COLORS['INFO']}2.2{COLORS['END']}] 闁哄被鍎撮-hostB 闁汇劌瀚槐鎶藉触閸絿鐝-)
    r = get("/stitch/by-agent-agent_id=agent-hostB")
    edges_b = r.get("edges", [])
    print(f"    hostB: {len(edges_b)} edge(s)")
    for e in edges_b:
        print(f"      {e['id']}: {e['source_agent']} 闁-{e['target_agent']} rel={e['relation']}")
    assert len(edges_b) >= 2, (
        f"hostB should have >= 2 stitch edges (inbound+outbound), got {len(edges_b)}"
    )

    # 2c: 濡ょ姴鐭侀惁-hostC 闁汇劌瀚槐鎶藉触閸絿鐝-    print(f"\n  [{COLORS['INFO']}2.3{COLORS['END']}] 闁哄被鍎撮-hostC 闁汇劌瀚槐鎶藉触閸絿鐝-)
    r = get("/stitch/by-agent-agent_id=agent-hostC")
    edges_c = r.get("edges", [])
    print(f"    hostC: {len(edges_c)} edge(s)")
    for e in edges_c:
        print(f"      {e['id']}: {e['source_agent']} 闁-{e['target_agent']} rel={e['relation']}")
    assert len(edges_c) == 1, f"hostC should have 1 stitch edge, got {len(edges_c)}"

    # 2d: 濡ょ姴鐭侀惁澶岀磽濠靛棙鍊ら弶鍫ｎ潐閳ь剝顔婄紞瀣媼閳╁啯娈-    print(f"\n  [{COLORS['INFO']}2.4{COLORS['END']}] 闁稿繈鍔岄惇顒傜磽濠靛棙鍊ょ紓浣哄枙椤-)
    r = get("/stitch/stats")
    print(f"    Stitch stats: {json.dumps(r, indent=6)}")
    edge_count = r.get("stitch_edges", 0)
    assert edge_count >= 2, f"Should have >= 2 total stitch edges, got {edge_count}"

    # 2e: 闁哄被鍎撮妤呮偨鏉堚晝闂柛姘墣缁旂喐绂嶈閺佹捇鎯冮崟顐ｇ鐟滆埇鍨荤划銊╁几-    #   闂侇偅淇虹换鍐蓟閵夘煈鍤-hostA 闁-hostC 闁哄鍎甸悰娆戞嫚娴ｇ晫绠鹃梺顐ｇ閳-    agents_involved = set()
    for e_list in [edges_a, edges_b, edges_c]:
        for e in e_list:
            agents_involved.add(e["source_agent"])
            agents_involved.add(e["target_agent"])

    print(f"\n  [{COLORS['INFO']}2.5{COLORS['END']}] 閺夆晝鍋ら埀顒佽壘濞存ê螞閳ь剟寮-)
    print(f"    婵炴垵顦-Agent: {agents_involved}")
    assert "agent-hostA" in agents_involved, "hostA missing from graph"
    assert "agent-hostB" in agents_involved, "hostB missing from graph"
    assert "agent-hostC" in agents_involved, "hostC missing from graph"
    print(f"  {COLORS['PASS']}闁-濞戞挸顦€靛矂寮垫ウ璺ㄧ闂侇偅鑹惧ù妯活殽瀹€鍐闂侇偅淇虹换鍎僀OLORS['END']}")

    return edges_a, edges_b, edges_c


def phase3_tls_fingerprint():
    """Phase 3: TLS 闁圭娲ㄥЧ妤侇殽瀹€鍐 闁-C2 鐎规悶鍎遍崣鍨熼埄鍐ㄧ彲"""
    print(f"\n{'='*60}")
    print(f"{COLORS['INFO']}Phase 3: TLS 闁圭娲ㄥЧ妤侇殽瀹€鍐 (C2 婵☆垪鍓濈€-{COLORS['END']}")
    print(f"{'='*60}")

    # 閻庤鐭粻鐔哥▔閳ь剟骞嶉悷鏉垮殥闁活厹鍎冲▓-Cobalt Strike 婵☆垪鍓濈€-JA3 闁圭娲ㄥЧ-    # (闁哄鍎撮崵婊堝礂椤掆偓缁-C2 JA3 閹- https://ja3er.com/)
    c2_ja3_samples = [
        # Cobalt Strike 濮掓稒顭堥-JA3 (闁稿繒顭堥悗-
        {"ja3": "a0e9f5d64349fb13191bc781f81f42e1", "comm": "beacon", "port": 443},
        # Metasploit default
        {"ja3": "b8b0b5d3c6f0b7c1d2e3f4a5b6c7d8e9", "comm": "meterpreter", "port": 8443},
        # Empire stager
        {"ja3": "c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e", "comm": "powershell", "port": 443},
    ]

    all_alerts = []

    for i, sample in enumerate(c2_ja3_samples):
        print(f"\n  [{COLORS['INFO']}3.{i+1}{COLORS['END']}] 婵炲鍔岄崣-C2 JA3: {sample['ja3'][:24]}...")

        # 闁革负鍔岄ˇ鍧楀矗妫颁礁鐦滈柡鍫ｆ〃缁楀倸螣閳╁啫鐝柣鈺冾焾閹捇鎯-JA3 (C2 闂傚棗妫涢崗銏㈡偘鐏炶壈绀-
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
                print(f"      {COLORS['WARN']}闁-C2 ALERT[{alert['id']}]: "
                      f"risk={alert['risk_score']}, hosts={alert['hosts']}{COLORS['END']}")

    # 濡ょ姴鐭侀惁- 闁煎嘲鍟块惃顖涙償閺冣偓濠€-1 濞-C2 闁告稑锕ㄩ-    print(f"\n  [{COLORS['INFO']}3.4{COLORS['END']}] C2 闁告稑锕ㄩ鐔沸ч崶銊㈠亾-)
    r = get("/ja3/alerts")
    alerts = r.get("alerts", [])
    print(f"    闁诡剝顕ч幉锛勬媰閿旇姤娈- {len(alerts)}")
    for a in alerts:
        print(f"      [{a['id']}] JA3={a['ja3'][:24]}... "
              f"risk={a['risk_score']} hosts={a['hosts']}")

    assert len(alerts) >= 1, (
        f"Should have >= 1 C2 alert with clustered atypical JA3, got {len(alerts)}"
    )

    # 濡ょ姴鐭侀惁澶愭⒖閸℃瑥鍙冨ǎ鍥ｅ墲娴-    r = get("/ja3/clusters")
    clusters = r.get("clusters", [])
    print(f"\n  [{COLORS['INFO']}3.5{COLORS['END']}] JA3 闂傚棗妫涢崗-")
    for cl in clusters:
        print(f"      JA3={cl['ja3'][:24]}... count={cl['count']} "
              f"hosts={cl['hosts']} is_c2={cl['is_c2']} risk={cl['risk_score']:.0f}")

    print(f"  {COLORS['PASS']}闁-C2 鐎殿喖鍊搁悥-JA3 婵☆偀鍋撴繛鏉戭儔閻涙瑧鎷犳笟鈧埀顒佷亢缁诲剝COLORS['END']}")
    return alerts, clusters


def phase4_performance_baseline():
    """Phase 4: 闁诡儸鍡楀幋闁糕晞娅ｉ崵-闁-100 Agents 閼-100 濞存粌顑勫▎-""
    print(f"\n{'='*60}")
    print(f"{COLORS['INFO']}Phase 4: 闁诡儸鍡楀幋闁糕晞娅ｉ崵搴ㄥ箮閵夈儲鍟瀧COLORS['END']}")
    print(f"{'='*60}")

    N_AGENTS = 100
    N_PER_AGENT = 100

    print(f"\n  [{COLORS['INFO']}4.1{COLORS['END']}] 闁告ê顑嗙粊- {N_AGENTS} agents 閼-{N_PER_AGENT} events = "
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

    # 濡ょ姴鐭侀惁澶愭⒓閻斿嘲鐏欐繛锝呭船鐎-    time.sleep(0.1)  # 缂佹稑顦欢鐔兼⒓閻斿嘲鐏欑紒瀣暱閻-    r = get("/queue/stats")
    q_depth = r.get("queue_depth", 0)
    enqueued = r.get("enqueued", 0)
    backlog = r.get("backlog", 0)
    print(f"    Queue:    depth={q_depth} enqueued={enqueued} backlog={backlog}")

    # 濡ょ姴鐭侀惁澶屾崉椤栨粍鏆-    print(f"\n  [{COLORS['INFO']}4.2{COLORS['END']}] 閻犱警鍨抽弫閬嶅闯閵娾晝宕ｉ悹-(100 agents 闁告帒妫濋崢銈夊礆-3 collectors)")
    post("/router/add-collector", {"id": "collector-1"})
    post("/router/add-collector", {"id": "collector-2"})
    post("/router/add-collector", {"id": "collector-3"})

    route_counts = {}
    for i in range(N_AGENTS):
        agent_id = f"agent-{i:04d}"
        r = get(f"/router/route-host_id={agent_id}")
        cid = r.get("collector", "")
        route_counts[cid] = route_counts.get(cid, 0) + 1

    print(f"    閻犱警鍨抽弫閬嶅礆閸℃顏- {json.dumps(route_counts, indent=6)}")
    assert len(route_counts) == 3, (
        f"All 3 collectors should receive routes, got {len(route_counts)}"
    )

    # 閻犱緤绱曢悾濠氬礆閸℃顏撮柛褍娲╅妴鈧柟-    values = list(route_counts.values())
    if len(values) > 1:
        imbalance = max(values) - min(values)
        print(f"    闁告帒妫楃粩鐑藉磻韫囨挻鈻- {imbalance} (閻℃帒锕ら惃顒傛惥婵犲倹缍嗛悶-")
    else:
        imbalance = 0

    # 闁诡儸鍡楀幋闁哄偆鍙€閳-    assert rps > 0, f"RPS should be > 0, got {rps}"

    print(f"\n  {COLORS['PASS']}闁-闁诡儸鍡楀幋闁糕晞娅ｉ崵搴∶圭€ｎ厾妲搁梺顐ｄ亢缁诲剝COLORS['END']}")

    return {
        "elapsed_ms": elapsed,
        "rps": rps,
        "memory_mb": memory_mb,
        "heap_mb": heap_mb,
        "queue_depth": q_depth,
        "route_imbalance": imbalance,
    }


# 闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛-# Main
# 闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛-

def main():
    print(f"{COLORS['INFO']}ProvidAPT 闂傚棗妫欓崹姘殽瀹€鍐闁煎瓨纰嶅﹢鐨桟OLORS['END']}")
    print(f"Harness: {BASE_URL}")
    print(f"Time:    {time.strftime('%Y-%m-%dT%H:%M:%S')}")

    # 婵☆偀鍋撻柡灞诲劥缁绘盯鏌呭顓涘亾-    print(f"\n  婵☆偀鍋撻柡-Harness 閺夆晝鍋ら埀顒佺閳-..")
    try:
        health = get("/health")
        print(f"  {COLORS['PASS']}闁-Harness 鐎规瓕灏换娑㈠箳椤ㄤ竼OLORS['END']}")
    except Exception as e:
        print(f"  {COLORS['FAIL']}闁-闁哄啰濮电涵鑸垫交閻愭潙澶-Harness: {e}{COLORS['END']}")
        print(f"  閻犲洭顥撻垾妯荤┍-Harness 鐎瑰憡褰冨﹢顏呮交閹邦垼鏀- go run ./cmd/collector/")
        sys.exit(1)

    start_time = time.time()
    results = {}

    try:
        # Phase 1: 婵☆垼浜滈幃婊呯矓鐠囨彃袟
        step1_edge_id = phase1_lateral_movement()
        results["phase1"] = {"edge_id": step1_edge_id}

        # Phase 2: 缂傚倹绻傞幃搴ㄥ礄閸℃瑢鈧﹢骞€-        edges_a, edges_b, edges_c = phase2_stitch_accuracy()
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

        # Phase 4: 闁诡儸鍡楀幋闁糕晞娅ｉ崵-        perf = phase4_performance_baseline()
        results["phase4"] = perf

    except AssertionError as e:
        print(f"\n{COLORS['FAIL']}闁-婵炴潙顑堥惁顖涘緞鏉堫偉袝: {e}{COLORS['END']}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{COLORS['FAIL']}闁-鐎殿喖鍊搁悥- {type(e).__name__}: {e}{COLORS['END']}")
        sys.exit(1)

    elapsed = time.time() - start_time

    # 闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺-    # Final Report
    # 闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺呮煡鍩￠幇銊︽珳闁崇儤鍔忛弲鏌ュ煛閹般劍娅滈柍鐑樺姀閺-    print(f"\n{'='*60}")
    print(f"{COLORS['INFO']}闁哄牃鍋撶紓浣哥墦閻涙瑧鎷犳担鐟靶撻柛娑橆渽COLORS['END']}")
    print(f"{'='*60}")
    print(f"  闁肩増顨嗗-             {elapsed:.1f}s")
    print(f"  Phase 1 (婵☆垼浜滈幃婊呯矓鐠囨彃袟):     {COLORS['PASS']}PASS{COLORS['END']}")
    print(f"    - hostA闁愁偅濮峯stB SSH (remote_call)")
    print(f"    - hostB闁愁偅濮峯stC SCP (lateral_move)")
    print(f"  Phase 2 (缂傚倹绻傞幃搴ㄥ礄閸℃瑢鈧﹢骞€-:  {COLORS['PASS']}PASS{COLORS['END']}")
    print(f"    - hostA edges: {results.get('phase2', {}).get('hostA_edges', 0)}")
    print(f"    - hostB edges: {results.get('phase2', {}).get('hostB_edges', 0)}")
    print(f"    - hostC edges: {results.get('phase2', {}).get('hostC_edges', 0)}")
    print(f"  Phase 3 (JA3 婵☆偀鍋撴繛-:    {COLORS['PASS']}PASS{COLORS['END']}")
    print(f"    - C2 alerts:   {results.get('phase3', {}).get('alerts', 0)}")
    print(f"    - JA3 cluster: {results.get('phase3', {}).get('clusters', 0)}")
    print(f"  Phase 4 (闁诡儸鍡楀幋闁糕晞娅ｉ崵-:    {COLORS['PASS']}PASS{COLORS['END']}")
    perf = results.get('phase4', {})
    print(f"    - RPS:         {perf.get('rps', 0):,}")
    print(f"    - Memory:      {perf.get('memory_mb', 0)} MB")
    print(f"    - Queue depth: {perf.get('queue_depth', 0)}")

    print(f"\n{COLORS['PASS']}{'='*60}")
    print(f"闁圭鍋撻柡鍫濐槹缁佸鎷犻弴鈶╁亾濮樺磭绠-闁-)
    print(f"{'='*60}{COLORS['END']}")


if __name__ == "__main__":
    main()
