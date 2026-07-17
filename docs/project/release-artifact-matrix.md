# Release Artifact Matrix

This matrix defines the minimum customer-ready artifact set for a commercial ProvidAPT release.

The root `dist/` directory is the canonical publication directory for release
handoff. Package builders may temporarily stage package files under
`build/dist/`, but `scripts/release/commercial-release.sh` copies those files to
`dist/` and removes the staging directory by default to avoid duplicate large
artifacts. Set `KEEP_BUILD_DIST=1` only when debugging package builders.

## Required Artifacts

| Artifact | Required | Evidence |
| --- | --- | --- |
| Linux daemon binary | yes | version, commit, and build date embedded |
| CLI binary | yes | version, commit, and build date embedded |
| tar archive | yes | listed in `checksums.txt`; smoke-tested on a clean Linux host |
| Debian package | yes | install, service start, upgrade, and uninstall logs |
| RPM package | yes | install, service start, upgrade, and uninstall logs |
| container image | yes | immutable tag, digest, labels, health check |
| Helm chart | yes | template render, install, upgrade, rollback, uninstall logs |
| monitoring bundle | yes | Prometheus rules, Alertmanager routing, and Grafana dashboard deploy through Ansible |
| SBOM SPDX JSON | yes | generated from the release tag |
| SBOM CycloneDX JSON | yes | generated from the release tag |
| checksum manifest | yes | `checksums.txt` with one SHA-256 entry per artifact |
| checksum signature | yes | `providapt-sign` Ed25519 bundle, detached GPG, Minisign, Cosign bundle, or equivalent evidence |
| checksum public key | conditional | required when `checksums.txt.sig` is produced by `providapt-sign` |
| vulnerability report | yes | dependency and container findings, with waivers when accepted |
| release evidence report | yes | exported release readiness report |

## Verification Commands

```bash
make release-commercial
make package-smoke-matrix

# Equivalent explicit release readiness check:
providaptctl -release-check \
  -config examples/config/providapt.local.toml \
  -release-evidence docs/project/release-evidence-v1.2.2.md \
  -release-waivers build/release-waivers.json \
  -release-checksums dist/checksums.txt \
  -release-checksums-signature dist/checksums.txt.sig \
  -release-artifacts-dir dist \
  -release-required-artifacts archive,deb,rpm \
  -release-sbom dist/sbom.spdx.json,dist/sbom.cdx.json \
  -release-check-out build/release-readiness.md
```

## Acceptance Rules

- Every published artifact must be built from the same release tag.
- Package artifacts must pass `make package-smoke-matrix` before customer handoff.
- Every published install artifact and SBOM in `dist/` must appear in `checksums.txt`; signature files, public keys, and readiness reports are release evidence and are excluded.
- Every entry in `checksums.txt` must resolve to an existing file and match its SHA-256 digest.
- Required artifact types are `archive`, `deb`, and `rpm` unless a signed release waiver is present.
- SBOM files must be generated in SPDX JSON and CycloneDX JSON formats.
- Container and Helm artifacts must include immutable version metadata.
- All warnings require either remediation or an approved waiver with an expiry date.

## Air-Gapped Bundle

The offline customer bundle must include:

- release packages and container image archive
- Helm chart and default values
- SBOMs, checksums, checksum signature, and checksum public key when applicable
- offline license instructions
- upgrade and rollback instructions
- installation, operations, API, and support documentation
- known limitations and accepted-risk notices
