# CLI Reference

This document covers the main ProvidAPT command-line tools in the `v1.2.3-rc.1` release line.

## Tools

### `providaptctl`

Primary CLI for daemon management and operational checks.

| Command | Flag | Description |
|---------|------|-------------|
| Status | `-status` | Query daemon health and event stats |
| Stop | `-stop` | Gracefully stop the daemon |
| Restart | `-restart` | Stop then start |
| Config | `-config <path>` | Specify config file |
| Diagnose | `-diagnose` | Collect diagnostic bundle |
| Release Check | `-release-check` | Run commercial handoff readiness checks |
| Purge | `-purge` | Purge stored data |
| eBPF Inspect | `-bpf` | Inspect eBPF programs and pinned maps |
| Verify Store | `-verify` | Check Pebble store consistency |
| Audit Log | `-audit` | Query the persistent audit log |
| JSON Output | `-json` | Emit JSON where supported |

Examples:

```bash
providaptctl -status
providaptctl -restart
providaptctl -config /etc/providapt/providapt.toml -status
providaptctl -diagnose
providaptctl -release-check -config /etc/providapt/providapt.toml
providaptctl -verify -json
providaptctl -audit -audit-cat=admin -json
```

For release evidence capture, combine the readiness check with JSON output:

```bash
providaptctl -release-check \
  -config /etc/providapt/providapt.toml \
  -release-evidence docs/project/release-evidence-v1.2.3-rc.1.md \
  -release-waivers build/release-waivers.json \
  -release-checksums dist/checksums.txt \
  -release-checksums-signature dist/checksums.txt.sig \
  -release-artifacts-dir dist \
  -release-handoff build/handoff/providapt-v1.2.3-rc.1-handoff.zip \
  -release-required-artifacts archive,deb,rpm,helm,monitoring \
  -release-sbom dist/sbom.spdx.json,dist/sbom.cdx.json \
  -release-check-out build/release-readiness.md \
  -json
```

`-release-check-out` writes Markdown by default, or structured JSON when the
path ends in `.json`.

`-release-waivers` accepts reviewed warning waivers in JSON. Waivers only apply
to active `WARN` checks; expired or malformed waivers fail the release check.

`-release-checksums` validates that the release checksum manifest exists,
contains at least one artifact entry, and uses `<sha256> <artifact>` rows.

`-release-artifacts-dir` verifies the actual SHA-256 digest of every artifact
listed in the checksum manifest.

`-release-handoff` validates a candidate handoff directory or zip package. It
checks that the package references the current version and commit and does not
contain stale approval markers from an older generated handoff.

`-release-required-artifacts` validates that the checksum manifest includes the
commercial artifact matrix. The default gate requires `archive`, `deb`, `rpm`,
`helm`, and `monitoring`; pass an empty value to disable this gate for
non-commercial builds.

`-release-checksums-signature` validates that a detached signature file for the
checksum manifest is present and non-empty. Recognized evidence formats include
GPG armored signatures, Minisign signatures, and Cosign bundle JSON.

`-release-sbom` validates one or more SPDX/CycloneDX JSON SBOM files. Separate
multiple paths with commas or semicolons.

```json
{
  "waivers": [
    {
      "check": "api_auth",
      "reason": "isolated customer acceptance environment",
      "approved_by": "release-manager",
      "expires": "2026-12-31"
    }
  ]
}
```

Control-plane support APIs:

- `POST /api/v1/control/support`
- `GET /api/v1/control/support/download`
- `GET /api/v1/control/audit?category=admin&source=supportbundle`
- `GET /api/v1/control/license`
- `POST /api/v1/control/license`
- `GET /api/v1/control/upgrade`
- `POST /api/v1/control/upgrade`

Key environment variables:

- `PROVIDAPT_LICENSE_PUBLIC_KEY_PATH`
- `PROVIDAPT_LICENSE_REVOCATION_URL`
- `PROVIDAPT_LICENSE_REVOCATION_CACHE`
- `PROVIDAPT_LICENSE_REVOCATION_SIG_URL`
- `PROVIDAPT_LICENSE_REVOCATION_SIG_CACHE`
- `PROVIDAPT_LICENSE_GRACE_PERIOD_DAYS`
- `PROVIDAPT_UPGRADE_DOWNLOAD_URL`
- `PROVIDAPT_UPGRADE_PACKAGE_PATH`
- `PROVIDAPT_UPGRADE_EXPECTED_SHA256`
- `PROVIDAPT_UPGRADE_SIGNATURE_PATH`
- `PROVIDAPT_UPGRADE_PUBLIC_KEY_PATH`
- `PROVIDAPT_UPGRADE_ROLLBACK_PLAN`

### `providapt-verify`

Verifies Pebble database integrity using Merkle tree anchors.

| Flag | Description | Default |
|------|-------------|---------|
| `-data` | Data directory path | `/var/lib/providapt/store` |
| `-verbose` | Show detailed verification info | `false` |
| `-output` | Write report to file | stdout |

Examples:

```bash
providapt-verify -data /var/lib/providapt/store
providapt-verify -data /var/lib/providapt/store -verbose
providapt-verify -data /var/lib/providapt/store -output /tmp/verify.txt
```

### `providapt-watchdog`

Monitors the main daemon and restarts on failure when used as a systemd companion.

```bash
providapt-watchdog
```

### `providapt-heal`

Post-incident remediation and impact assessment helper.

| Subcommand | Description |
|------------|-------------|
| `assess` | Analyze blast radius from a compromised node |
| `rollback` | Attempt file-level rollback from provenance |
| `block` | Generate blocking rules |
| `migrate` | Migrate data store between locations |

Examples:

```bash
providapt-heal assess -pid 1234
providapt-heal block -ip 10.0.0.5 -port 4444
providapt-heal migrate -from /var/lib/providapt/store-old -to /var/lib/providapt/store
```

### `providapt-deanon`

Resolves anonymized node IDs for forensic analysis.

```bash
providapt-deanon -node "p:1234"
providapt-deanon -file nodes.txt -json > resolved.json
```

## Makefile Targets

### Build

| Target | Description |
|--------|-------------|
| `make build-core` | Full product build (eBPF + userspace) |
| `make build-ebpf` | Compile eBPF programs only |
| `make build-userspace` | Compile Go binaries only |
| `make install-local` | Build and install to the local system |
| `make demo` | Build the collector demo |

### Test

| Target | Description |
|--------|-------------|
| `make test` | Run all core unit tests |
| `make ext-test` | Run extended engine, storage, and policy tests |
| `make cluster-test` | Run stitcher and cluster tests |
| `make graphsketch-test` | Run graph sketch tests |
| `make deception-test` | Run deception tests |
| `make supplychain-test` | Run supply-chain tests |

### Operations

| Target | Description |
|--------|-------------|
| `make run` | Build and run the daemon |
| `make stop` | Stop the daemon |
| `make restart` | Restart the daemon |
| `make cgroup` | Configure cgroup limits |
| `make attack-sim` | Run attack simulation |
| `make verify-capture` | Verify provenance capture |
