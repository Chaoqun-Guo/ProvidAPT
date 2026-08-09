# Upgrade Guide

This guide covers upgrade preparation for the current maintained release line.

## Target Release

- Current release: `v1.2.2`
- Recommended upgrade mode: in-place package upgrade with preflight validation

## Pre-Upgrade Checklist

1. Confirm a recent backup of the data directory
2. Verify current version, artifact hash, and rollback readiness
3. Prepare the rollback plan and package checksum
4. Confirm the target host has required kernel, BTF, and libbpf prerequisites

## Recommended Procedure

```bash
# 1. Verify current state
providaptctl -status
providapt-verify -data /var/lib/providapt/store

# 2. Run upgrade preflight
sudo scripts/upgrade/preflight-linux.sh
sudo EXPECTED_SHA256=<sha256> scripts/upgrade/preflight-linux.sh /path/to/package.tar.gz

# 3. Prepare binaries or packages
make build-core
bash build/packages/build_all.sh auto

# 4. Install on the target host
sudo scripts/install/install-linux.sh

# 5. Validate the service
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

## Build Published Upgrade Artifacts

Create the artifact manifest, checksum file, and optional HMAC signature before
publishing a staged upgrade:

```bash
make upgrade-artifact \
  ARTIFACT=dist/providapt-linux-amd64.tar.gz \
  VERSION=v1.2.4 \
  BASE_URL=http://auth.example.com:19090/artifacts \
  SIGNING_KEY="$PROVIDAPT_UPGRADE_SIGNING_KEY" \
  OUT_DIR=build/upgrade-artifacts
```

Outputs:

| File | Purpose |
| --- | --- |
| `build/upgrade-artifacts/<artifact>` | Artifact copied into the publish directory |
| `build/upgrade-artifacts/<artifact>.sha256` | Package checksum evidence |
| `build/upgrade-artifacts/<artifact>.sig` | HMAC signature over the package SHA256 when `SIGNING_KEY` is set |
| `build/upgrade-artifacts/latest.json` | Manifest consumed by `/v1/releases/latest` and the dashboard |
| `build/upgrade-artifacts/upgrade-artifact.md` | Operator-readable release evidence |

Publish the generated values through your open-source release manifest or artifact host:

```bash
export PROVIDAPT_UPGRADE_DOWNLOAD_URL=https://downloads.example.com/providapt-linux-amd64.tar.gz
export PROVIDAPT_UPGRADE_SHA256=<expected_sha256>
export PROVIDAPT_UPGRADE_SIGNATURE_URL=https://downloads.example.com/providapt-linux-amd64.tar.gz.sig
```

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
- `scripts/upgrade/preflight-linux.sh`

Adapt the script to your packaging model, service manager, and backup layout before production rollout.
