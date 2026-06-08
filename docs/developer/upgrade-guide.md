# Upgrade & Migration Guide

**v1 → v2 → v2.2** | Database Migration, Kernel Upgrade, Hot-Reload

---

## 1. Version Compatibility Matrix

| From | To | Data Compatible | Config Compatible | Rollback |
|------|----|-----------------|-------------------|----------|
| v1.x | v2.0 | Full (Pebble) | Full | Full |
| v2.0 | v2.1 | Full | Partial | Data only |
| v2.1 | v2.2 | Full | Full | Full |

## 2. Database Migration (v1 → v2.2)

### 2.1 Pre-Migration Checks

```bash
# Verify current version
providaptctl -status | grep Version

# Check data integrity
providapt-verify -data /var/lib/providapt/store

# Backup current data
mkdir -p /backup/providapt-pre-migration
cp -a /var/lib/providapt/store /backup/providapt-pre-migration/
```

### 2.2 Migration Steps

```bash
# 1. Stop current daemon
systemctl stop providapt

# 2. Install new version
make v1-install

# 3. Run data migration
providapt-heal -migrate /var/lib/providapt/store

# 4. Verify migrated data
providapt-verify -data /var/lib/providapt/store

# 5. Start new daemon
systemctl start providapt

# 6. Verify operation
providaptctl -status
tail -f /var/log/providapt/providapt.log | head -10
```

### 2.3 Schema Changes (v2.0 → v2.2)

| Change | Version | Description |
|--------|---------|-------------|
| Node attrs map | v2.0 | `map[string]interface{}` |
| Added supply_chain attrs | v2.2 | `package_name`, `package_version`, `sbom_ref`, `supply_chain_risk` |
| Added mem_forensic attrs | v2.2 | `mem_forensic`, `mem_trigger`, `mem_risk_level`, `mem_matches` |
| Added honeypot attrs | v2.2 | `honeypot_triggered`, `confirmed_malicious`, `frozen_cgroup` |
| Global Node format | v2.2 | Added `attrs` field (map[string]string) for cross-host attrs |

## 3. Kernel Upgrade

### 3.1 Hot-Reload Workflow

Kernel upgrades that preserve eBPF BTF compatibility do not require changes to ProvidAPT. For major version jumps:

```bash
# 1. Verify new kernel has BTF
ls /sys/kernel/btf/vmlinux

# 2. Reload eBPF programs (no daemon restart needed)
providaptctl -reload-ebpf

# 3. Verify programs loaded
bpftool prog list | grep providapt
```

### 3.2 Kernel Version Matrix

| Kernel | BTF | CO-RE | Notes |
|--------|-----|-------|-------|
| 5.11–5.18 | Manual | Partial | Requires `CONFIG_DEBUG_INFO_BTF` |
| 5.19–6.1 | Built-in | Full | Recommended minimum |
| 6.2+ | Built-in | Full | Fully supported |
| 6.6+ | Built-in | Full | Long-term stable |

## 4. Configuration Migration

```toml
# v2.0 config (minimal)
[agent]
scan_interval = "30s"

# v2.2 config (with all new modules)
[agent]
scan_interval = "30s"
deep_taint_threshold = 3

[patterns]
enabled = ["SENSITIVE_EXFIL", "SCRIPT_CHILD", "DEEP_TAINT_CHAIN", "PRIVILEGE_ESCALATION", "MEMORY_ANOMALY"]

[graphsketch]
enabled = true
entropy_alpha = 0.3
entropy_threshold = 3.0

[supplychain]
enabled = true
sbom_path = "/etc/providapt/sbom/"

[deception]
enabled = true
overlay_dir = "/tmp/providapt-honeypot"

[transport]
compression = "zstd"
enable_hash_cache = true
```

New configuration required when upgrading to v2.2:
- `[graphsketch]` section for entropy detection
- `[supplychain]` section for SBOM monitoring
- `[deception]` section for honeytoken injection
- `[transport]` section for distributed features

## 5. Control-Plane Upgrade Preflight

ProvidAPT now supports a release-oriented upgrade validation path from the control plane.

Recommended sequence:

1. Configure:
   - `upgrade.download_url`
   - `upgrade.package_path`
   - `upgrade.expected_sha256`
   - `upgrade.signature_path`
   - `upgrade.public_key_path` or `upgrade.signing_key`
   - `upgrade.rollback_plan`
2. Run control-plane `download`
3. Run control-plane `preflight`
4. Confirm:
   - `package_verified=true`
   - `signature_verified=true` when signature verification is enabled
   - `rollback_ready=true`
   - `preflight_ready=true`

If remote license revocation is enabled for the same deployment, confirm:

- `revocation_verified=true`
- cached revocation data is available for offline fallback

## 6. Rollback Skeleton

An example rollback entry point is available at:

- `scripts/upgrade/rollback-example.sh`

This script is intentionally a skeleton and should be adapted per packaging model, service manager, and backup layout before a production rollout.
