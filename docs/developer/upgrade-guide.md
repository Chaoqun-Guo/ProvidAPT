# Upgrade Guide

This guide covers upgrade preparation for the current maintained release line.

## Target Release

- Current release: `v1.2.2`
- Recommended upgrade mode: in-place package upgrade with preflight validation

## Pre-Upgrade Checklist

1. Confirm a recent backup of the data directory
2. Verify license status and revocation state
3. Prepare the rollback plan and package checksum
4. Confirm the target host has required kernel, BTF, and libbpf prerequisites

## Recommended Procedure

```bash
# 1. Verify current state
providaptctl -status
providapt-verify -data /var/lib/providapt/store

# 2. Prepare binaries
make build-core

# 3. Install on the target host
sudo make install-local

# 4. Validate the service
sudo systemctl restart providapt
providaptctl -status
```

## Control-Plane Upgrade Preflight

Configure:

- `upgrade.download_url`
- `upgrade.package_path`
- `upgrade.expected_sha256`
- `upgrade.signature_path`
- `upgrade.public_key_path` or `upgrade.signing_key`
- `upgrade.rollback_plan`

Then run:

1. control-plane `download`
2. control-plane `preflight`

Confirm:

- `package_verified=true`
- `signature_verified=true` when signature validation is enabled
- `rollback_ready=true`
- `preflight_ready=true`

## Rollback Skeleton

Use:

- `scripts/upgrade/rollback-example.sh`

Adapt the script to your packaging model, service manager, and backup layout before production rollout.
