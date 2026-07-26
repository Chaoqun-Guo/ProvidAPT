# Detection Rules & Sigma Integration Guide

**Rule Authoring** | Sigma-to-ProvidAPT Mapping, YAML Policy Format

---

## 1. Sigma Rule Conversion

### 1.1 Mapping Sigma Fields to ProvidAPT

| Sigma Field | ProvidAPT Equivalent | Example |
|-------------|---------------------|---------|
| `EventID` | Event type enum | `EV_PROCESS_EXEC (2)` |
| `Image` | Process comm | `comm: "powershell"` |
| `CommandLine` | Process cmdline attrs | `attrs.cmdline` |
| `TargetFilename` | File path | `f.path` |
| `SourceIp` | Network source | `n.src_ip` |
| `DestinationIp` | Network destination | `n.dst_ip` |
| `DestinationPort` | Network port | `n.dst_port` |
| `User` | UID | `p.uid` |
| `ParentImage` | Parent comm | `p.ppid -> parent.comm` |

### 1.2 Conversion Examples

**Sigma: Suspicious PowerShell Download**
```yaml
title: PowerShell Download from Suspicious URL
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'DownloadString'
  condition: selection
```

**ProvidAPT Pattern**
```go
// PatSensitiveExfil handles this case when the tainted process
// uses PowerShell to download and execute remote content.
// Additional check: fileless execution via pipe_reader attribute.
if p.comm == "powershell" || p.comm == "pwsh" {
    if strings.Contains(cmdline, "DownloadString") || 
       strings.Contains(cmdline, "Invoke-Expression") {
        // Mark as high suspicion, trigger memory forensics
    }
}
```

**Sigma: Suspicious LSASS Access**
```yaml
title: LSASS Process Access
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantAccess|contains: 'PROCESS_ALL_ACCESS'
  condition: selection
```

**ProvidAPT Pattern**
```go
// CredentialCorrelator (internal/policy/blastradius/) detects
// credential theft by correlating:
//   1. Process opens /proc/<lsass_pid>/mem or similar
//   2. Same process later makes remote login (SSH/RDP)
```

---

## 2. YAML Policy Format

### 2.1 Rule Structure

```yaml
# /etc/providapt/rules/custom_rules.yaml
rules:
  - id: "SC-001"
    name: "Unauthorized File Download"
    description: "Detect curl/wget writing to system directories"
    severity: critical
    tags: ["supply_chain", "t1105"]
    detection:
      - match: file_write
        conditions:
          - source.comm IN ["curl", "wget", "nc"]
          - target.path PREFIX "/usr/bin/"
          - target.path PREFIX "/usr/sbin/"
          - target.path PREFIX "/opt/"
    response:
      - alert
      - memory_scan
      - freeze_process

  - id: "SC-002"
    name: "Unsigned Package Installation"
    description: "Package installed without GPG signature verification"
    severity: high
    tags: ["supply_chain", "t1195"]
    detection:
      - match: package_install
        conditions:
          - package.signing_verified = false
          - package.manager IN ["apt", "dpkg", "rpm"]
    response:
      - alert
      - sbom_check
```

### 2.2 Detection Conditions

| Operator | Description | Example |
|----------|-------------|---------|
| `=` | Equality | `comm = "bash"` |
| `!=` | Inequality | `uid != 0` |
| `IN` | Set membership | `comm IN ("bash", "sh", "zsh")` |
| `PREFIX` | String prefix | `path PREFIX "/etc/"` |
| `SUFFIX` | String suffix | `path SUFFIX ".php"` |
| `CONTAINS` | Substring | `cmdline CONTAINS "DownloadString"` |
| `>` / `<` | Numeric comparison | `depth > 3` |
| `MATCHES` | Regex | `path MATCHES ".*evil.*"` |

### 2.3 Response Actions

| Action | Description |
|--------|-------------|
| `alert` | Generate alert to channel |
| `memory_scan` | Trigger on-demand memory forensics |
| `freeze_process` | CGroup freeze + context capture |
| `block_ip` | Network block via iptables |
| `block_comm` | Block process execution |
| `sbom_check` | Cross-reference SBOM database |
| `upload_full_graph` | Force full data upload to central |

---

## 3. Built-in Detection Patterns

| Pattern ID | Name | Severity | Description |
|-----------|------|----------|-------------|
| `SENSITIVE_EXFIL` | Sensitive Exfiltration | HIGH | Sensitive file read + network connection |
| `SCRIPT_CHILD` | Script Child Execution | CRITICAL | Tainted process write -> exec chain |
| `DEEP_TAINT_CHAIN` | Deep Taint Chain | MEDIUM | Propagation depth >= 3 hops |
| `PRIVILEGE_ESCALATION` | Privilege Escalation | HIGH | Tainted process with setuid |
| `MEMORY_ANOMALY` | Memory Anomaly | CRITICAL | mprotect RW->RX or fileless execution |
| `SUPPLY_CHAIN_CRITICAL` | Supply Chain Critical | CRITICAL | Untrusted writer to system dir |
| `SUPPLY_CHAIN_HIGH` | Supply Chain High | HIGH | Unsigned package in system dir |
| `ENTROPY_ANOMALY` | Behavior Entropy Spike | HIGH | KL divergence > threshold |
| `HONEYPOT_TRIPWIRE` | Honeytoken Trigger | CRITICAL | Process accessed phantom file |
| `MEMORY_YARA_MATCH` | YARA Memory Match | CRITICAL | Malicious pattern in process memory |

---

## 4. Rule Testing

```bash
# Test a rule against historical data
providaptctl -test-rule /etc/providapt/rules/custom_rules.yaml

# Output:
# SC-001: 47 matches in last 24h
# SC-002: 12 matches in last 24h

# Dry-run a new pattern
providaptctl -dry-run -pattern "SENSITIVE_EXFIL" -since "1h"

# Export matched events
providaptctl -export -rule "SC-001" -output /tmp/matches.json
```
## 5. Alert Feedback and Detection Tuning

Analysts can attach feedback to alert workflow records. This feedback is useful
for detector tuning and supervised evaluation.

```bash
curl -X POST http://<server>:18080/api/v1/control/alerts \
  -H "Content-Type: application/json" \
  -d '{"action":"annotate","alert_id":"alert-a","classification":"false_positive","note":"approved maintenance command"}'
```

Supported classifications:

| Classification | Meaning |
| --- | --- |
| `true_positive` | confirmed malicious or policy-violating activity |
| `false_positive` | alert fired on accepted benign activity |
| `benign` | normal activity, not useful for detection |
| `duplicate` | already represented by another alert |
| `needs_review` | analyst has not completed triage |

The annotation is stored in alert `details.classification` and
`details.classification_updated_at`, so exports can join analyst feedback with
ground-truth and ATT&CK coverage reports.
