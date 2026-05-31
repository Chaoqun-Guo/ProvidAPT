# Taint Propagation & Risk Scoring Standard

**Version 2.2** | Mathematical Model, Scoring Tables, and Alert Severity

---

## 1. Taint Propagation Algorithm

### 1.1 Overview

Taint propagation follows a BFS (Breadth-First Search) fixpoint iteration over the provenance graph. Starting from initial seeds (untrusted processes, sensitive files, network-facing services), taint spreads along edges with per-hop decay.

### 1.2 Initial Seeds

Taint seeds are categorized into three sources:

| Source | Level | Examples |
|--------|-------|----------|
| Network-facing processes | `TAINT_CRITICAL (4)` | nginx, apache2, sshd, php-fpm, tomcat |
| Network tools | `TAINT_MEDIUM (2)` | curl, wget, nc, scp, sftp |
| Sensitive files | `TAINT_HIGH (3)` | /etc/shadow, /etc/passwd, /etc/ssh/\*, /root/\* |

### 1.3 Propagation Rules

```
For each seed S with taint level L:
    worklist ← [S]

    while worklist is not empty:
        current ← pop(worklist)
        tn ← taint_node[current]

        // Forward propagation: source → target
        for each edge E from current:
            next_level ← tn.level - 1
            if next_level ≥ TAINT_LOW:
                try_taint(E.target, next_level)

        // Reverse propagation: target → source
        for each edge E to current:
            next_level ← tn.level - 1
            if next_level ≥ TAINT_LOW:
                try_taint(E.source, next_level)
```

### 1.4 Decay

Each propagation hop reduces taint by exactly one level:

```
TAINT_CRITICAL (4) → TAINT_HIGH (3) → TAINT_MEDIUM (2) → TAINT_LOW (1) → TAINT_NONE (0)
```

### 1.5 Try-Taint Logic

```go
func tryTaint(id, prevID, relation string, level TaintLevel) {
    existing = tainted[id]
    if existing != nil && existing.level ≥ level {
        return  // Existing taint is stronger — skip
    }
    newDepth = tainted[prevID].depth + 1
    tainted[id] = {level, newDepth, prevID, relation, reasons}
}
```

### 1.6 Propagation Path

The full chain from seed to leaf is preserved via `PrevID` pointers:

```
Attacker curl (CRITICAL, depth=0)
  → bash (HIGH, depth=1)
    → python3 (MEDIUM, depth=2)
      → wget (LOW, depth=3)
```

---

## 2. Risk Scoring Matrix

### 2.1 Pattern Severity

| Detection Pattern | Base Severity | Scenario |
|------------------|--------------|----------|
| PatSensitiveExfil | HIGH | Tainted process reads sensitive file AND connects to external IP |
| PatScriptChild | CRITICAL | Tainted process writes script → another process executes it |
| PatDeepTaint | MEDIUM | Propagation depth ≥ 3 hops |
| PatPrivEsc | HIGH | Tainted process with setuid |
| PatMemoryAnomaly | CRITICAL | mprotect RW→RX or fileless execution |
| Supply Chain Critical | CRITICAL | Untrusted writer to system directory |
| Supply Chain High | HIGH | Unsigned package in system directory |
| Entropy Spike | HIGH | KL divergence > mean + 3σ |
| Honeytoken Tripwire | CRITICAL | Process accessed phantom file |

### 2.2 Supply Chain Risk Factors

| Signal | Score | Threshold |
|--------|-------|-----------|
| `RiskFactorUntrustedWriter` | +60 | curl/wget writes to /usr/bin → CRITICAL |
| `RiskFactorUnsignedPackage` | +50 | Package signature verification fails → HIGH |
| `RiskFactorNoSBOM` | +30 | Binary not found in any SBOM → MEDIUM |
| `RiskFactorTamperedAfterInstall` | +70 | Non-pm process modifies installed file → CRITICAL |
| `RiskFactorUntrustedRepo` | +40 | Package from non-official repository → HIGH |
| `RiskFactorKnownVulnerability` | +25 | Known CVE in package version → MEDIUM |
| `RiskFactorSuspiciousOrigin` | +35 | Unknown process writes to system dir → MEDIUM |

Risk Level Thresholds:
```
Score 0-19:   LOW
Score 20-39:  MEDIUM
Score 40-59:  HIGH
Score 60-100: CRITICAL
```

### 2.3 Memory Forensics Risk

| YARA Match Type | Severity | Example Rules |
|----------------|----------|---------------|
| C2 beacon | Critical | `CS_BEACON_MUTEX`, `CS_BEACON_PIPE` |
| Shellcode execution | Critical | `EXECVE_BINSH`, `SHELLCODE_FORK` |
| Reflective loader | High | `REFLECTIVE_LOADER` |
| Meterpreter | Critical | `METERPRETER_STAGE` |
| Memory-mapped ELF | High | `ELF_MAGIC_ANON` |
| Fileless execution | Medium | `MEMFD_REFERENCE` |
| PowerShell cradle | High | `PS_DOWNLOAD_CRADLE` |
| Bind shell | Critical | `BINDSHELL_4444` |
| NOP sled | Low | `NOP_SLED_LARGE` |
| RC4 key schedule | Medium | `RC4_KEY_SCHEDULE` |

Memory Risk Score: `min(sum(match_severity_weights), 100)` with dedup (same rule counted once).

### 2.4 Blast Radius Risk

Cross-host risk scoring combines host-level impacts:

```go
impact.riskScore = len(processes)*10 + len(files)*5 + len(networks)*15
isCritical = riskScore > 50
```

---

## 3. Entropy Detection Model

### 3.1 Edge Type Distribution

Build probability distribution from edge type counts in each scan window:

```go
P(type_i) = count(type_i) / total_edges
```

### 3.2 Baseline Update (EMA)

```go
// First window: initialize
baseline[type] = P_current[type]

// Subsequent windows: exponential moving average
baseline[type] = (1-α) * baseline[type] + α * P_current[type]

// α = 0.3 (default), configurable
```

### 3.3 KL Divergence

```
KL(P_current || P_baseline) = Σ P_current(i) * ln(P_current(i) / P_baseline(i))
```

Where:
- P_current(i) = probability of edge type i in current window
- P_baseline(i) = EMA-smoothed probability from history
- Types not in baseline: use ε = 1e-10 to avoid division by zero

### 3.4 Anomaly Threshold

```
Running stats over last N=20 KL values:
  kl_mean = mean(history)
  kl_stddev = sample_stddev(history)

Anomaly if:  kl_current > kl_mean + 3.0 * kl_stddev
            AND windows_seen ≥ 5
```

---

## 4. Scoring Aggregate Pipeline

```
Raw Event → eBPF Taint (kernel)
  → Provenance Graph → Analyzer (userspace)
    → Pattern Match → Alert with Severity
    → Graph Sketch → Feature Vector → Entropy Check
      → KL divergence > threshold? → Force Upload
    → Memory Check → mprotect detected? → YARA Scan
      → Match found? → CRITICAL alert
    → Supply Chain Check → package install?
      → PackageInfo → Risk Score → Node Attribute
```

### 4.1 Alert Deduplication

Alerts are deduplicated by `PatternID + AlertNodeID`. The first alert for a given (pattern, node) pair is emitted; duplicates are silently dropped within the same scan window.

### 4.2 Subgraph Extraction

Each alert carries a subgraph showing the attack path:

1. Trace `PrevID` pointers from alert node back to initial seed
2. Collect all nodes on the path
3. Add 1-hop neighbours as context
4. Collect edges whose endpoints are in the set

The subgraph enables analysts to visualize the full attack chain from a single alert.
