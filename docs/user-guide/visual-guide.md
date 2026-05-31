# Visualization & Analysis Guide

**Graph Interpretation** | Color Coding, Timeline, AI-Generated Reports

---

## 1. Graph Visualization

### 1.1 Node Types & Colors

| Node Type | Color | Icon | Description |
|-----------|-------|------|-------------|
| Process | Blue | `⚙` | Executing process (activity) |
| File | Green | `📄` | File on disk or memory-mapped |
| Network | Orange | `🌐` | IP:port endpoint |
| Memory | Purple | `🧠` | mprotect RX region |
| Pipe | Gray | `🔗` | Inter-process pipe |
| Package | Teal | `📦` | Software package (SBOM) |
| Credential | Yellow | `🔑` | Security context / identity |

### 1.2 Edge Relations & Styles

| Relation | Line Style | Arrow | Description |
|----------|-----------|-------|-------------|
| `prov:used` | Solid | → | Process read/connected to entity |
| `prov:wasGeneratedBy` | Solid | ← | Entity created by process |
| `prov:wasInformedBy` | Dashed | → | Causality (fork, IPC) |
| `prov:wasDerivedFrom` | Dotted | → | Version chain |
| `prov:wasAttributedTo` | Dashed | ↔ | Package attribution |

### 1.3 Taint Indicators

Process nodes display a severity badge:

```
┌──────────────────┐
│  [p:1234] bash  │  ← Node ID + label
│  ⚠ CRITICAL     │  ← Taint severity badge
│  ─────────────  │
│  PID: 1234      │  ← Attribute detail
│  UID: 0         │
│  fileless: true │
│  shellcode: true│
└──────────────────┘
```

Badge colors:
- **Gray**: No taint
- **Yellow**: LOW / MEDIUM
- **Orange**: HIGH
- **Red**: CRITICAL

Special badges:
- `🐚`: Shellcode detected
- `📂`: Fileless execution
- `🔌`: Network connection
- `🔒`: Setuid escalation
- `🎣`: Honeytoken triggered
- `📦`: Package manager activity

### 1.4 Timeline Controls

```
[← 1h] [← 15m] [← 5m] [NOW] [→ 5m] [→ 15m]
         ████████████████████░░░░░░░░
         │   Attack window    │
    09:00:00              09:15:00

Timeline features:
- Drag to pan time window
- Scroll wheel to zoom
- Click node to see event timeline
- Select range to isolate subgraph
```

---

## 2. Subgraph Extraction

When an alert fires, the analyzer extracts a subgraph showing the attack path:

```
                    ┌──────────┐
           ┌──────▶│ f:evil.php│
           │       └──────────┘
     ┌──────────┐       │
     │ apache2  │       │ wasGeneratedBy
     │ (MEDIUM) │       ▼
     └──────────┘   ┌──────────┐
           │        │python3   │
           │        │(CRITICAL)│
           │        │fileless  │
           │        │shellcode │
           │        └────┬─────┘
           │             │
           │     ┌───────▼───────┐
           │     │  memfd:anon   │
           │     │  (fileless)   │
           │     └───────────────┘
           │
           ▼
     ┌──────────┐
     │ n:C2:443 │
     │ (exfil)  │
     └──────────┘
```

Visual cues:
- **Bold borders**: Nodes on the main attack path
- **Dashed borders**: 1-hop context nodes
- **Red tinted**: Tainted nodes with CRITICAL severity
- **Timestamps**: Edge labels show event timing

---

## 3. AI-Generated Attack Reports

When a `PatDeepTaint` or `PatMemoryAnomaly` alert fires, the system generates a natural-language report:

```markdown
## Attack Summary
**Severity**: CRITICAL | **Pattern**: Supply Chain + Memory Anomaly
**Detected**: 2026-05-28T14:23:00Z

### Attack Chain
1. **Initial Access** — pip3 installed `evil-package==1.0.0` from pypi.org
   - Package not GPG signed (signing_verified: false)
   - Supply chain risk: CRITICAL

2. **Execution** — python3 executed `evil_package/runner.py`
   - Created anonymous memfd (fileless execution)
   - mprotect RW→RX detected (shellcode injection)

3. **Defense Evasion** — PTACE_TRACEME privilege escalation
   - Process injected into apache2 (uid 1000 → 0)

4. **Lateral Movement** — SSH connection to host-app-01:22
   - Cross-host stitch matched (flow: web-01 → app-01)
   - Taint propagated: CRITICAL → HIGH

5. **Exfiltration** — curl HTTPS to 198.51.100.99:443
   - JA3 fingerprint: Cobalt Strike Beacon (6734f374)
   - Config file /etc/db_config.ini modified

### Forensic Artifacts
- **Memory Dump**: 3 YARA matches (CS_BEACON_MUTEX, ELF_MAGIC_ANON)
- **Network Flows**: 2 hosts affected (host-app-01, host-c2-01)
- **Process Context**: PID 1337, cmdline: python3 -c evil_runner
```

---

## 4. Export Formats

| Format | Extension | Tool | Use Case |
|--------|-----------|------|----------|
| PROV-JSON | `.json` | Any JSON viewer | Machine analysis |
| GraphML | `.graphml` | yEd, Gephi | Visual graph exploration |
| Cytoscape JSON | `.cyjs` | Cytoscape | Network analysis |
| SVG | `.svg` | Browser | Report inclusion |
| PDF | `.pdf` | Browser print | Compliance documentation |

```bash
# Export current graph
curl -s http://localhost:8722/graph/nodes > graph.json

# Export subgraph for a specific alert
curl -s "http://localhost:8722/graph/backtrack?node_id=p:1234" > subgraph.json

# Convert to SVG (requires graphviz)
python3 -c "
import json, sys
data = json.load(open('graph.json'))
# Convert to DOT format for Graphviz
print('digraph ProvidAPT {')
for node in data['nodes']:
    print(f'  \"{node[\"id\"]}\" [label=\"{node[\"label\"]}\"]')
for edge in data.get('edges', []):
    print(f'  \"{edge[\"source\"]}\" -> \"{edge[\"target\"]}\"')
print('}')
" | dot -Tsvg -o graph.svg
```
