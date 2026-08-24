# Release Artifact Matrix

This matrix defines the minimum operator-ready artifact set for an open-source ProvidAPT release.

The root `dist/` directory is the canonical publication directory for release
handoff. Package builders may temporarily stage package files under
`build/dist/`, but `scripts/release/open-source-release.sh` copies those files to
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
| container image archive | conditional | required for offline or air-gapped handoff; immutable tag, digest, labels, health check |
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
make release-open-source
make package-smoke-matrix
make github-actions-evidence
make artifact-signing-gate
make release-evidence-consistency-gate
make operator-release-gate

# Use explicit host mode only on disposable Linux validation hosts when Docker
# registry access is unavailable; it installs and purges the Debian package on
# the host, and validates RPM metadata/extraction without installing the RPM.
PACKAGE_SMOKE_MODE=host make package-smoke-matrix

# Aggregate all operator-release blockers into one JSON/Markdown report:
make operator-release-gate \
  RELEASE_GATES_JSON=build/release-gate-status.json \
  RELEASE_EVIDENCE_CONSISTENCY_GATE=build/release-evidence/release-evidence-consistency-gate.json \
  PACKAGE_SMOKE_DIR=build/package-smoke \
  PRODUCTION_READINESS_GATE=build/production-readiness/production-readiness-gate.json \
  ML_READINESS_GATE=build/ml-readiness/ml-readiness-gate.json \
  OPERATIONS_READINESS_GATE=build/operations-readiness/operations-readiness-gate.json \
  OPEN_SOURCE_READINESS_GATE=build/open-source-readiness/open-source-readiness-gate.json

# To replace a controlled local CI waiver with real GitHub Actions evidence:
make github-actions-evidence
make release-gates CI_EVIDENCE=build/ci/github-actions-evidence.json

# If blocked, convert the gate output into an owner-ready backlog:
make release-blocker-backlog \
  OPERATOR_RELEASE_GATE=build/operator-release/operator-release-gate.json

# Equivalent explicit release readiness check:
providaptctl -release-check \
  -config examples/config/providapt.local.toml \
  -release-evidence docs/project/release-evidence-v1.2.3-rc.1.md \
  -release-waivers build/release-waivers.json \
  -release-checksums dist/checksums.txt \
  -release-checksums-signature dist/checksums.txt.sig \
  -release-artifacts-dir dist \
  -release-required-artifacts archive,deb,rpm,helm,monitoring \
  -release-sbom dist/sbom.spdx.json,dist/sbom.cdx.json \
  -release-check-out build/release-readiness.md
```

## Acceptance Rules

- Every published artifact must be built from the same release tag.
- Package artifacts must pass `make package-smoke-matrix` before operator handoff.
- `make operator-release-gate` must pass before final operator delivery. A warning is acceptable only for a named, controlled local handoff; public publication requires all operator-release sections to pass.
- `make release-blocker-backlog` must produce zero release-blocking tasks before final publication.
- Every published install artifact and SBOM in `dist/` must appear in `checksums.txt`; signature files, public keys, and readiness reports are release evidence and are excluded.
- Every entry in `checksums.txt` must resolve to an existing file and match its SHA-256 digest.
- Release readiness, scan manifest, SBOM files, artifact signing evidence,
  release version, and commit must pass `make release-evidence-consistency-gate`.
- Required release artifact types are `archive`, `deb`, `rpm`, `helm`, and `monitoring` unless a signed release waiver is present.
- SBOM files must be generated in SPDX JSON and CycloneDX JSON formats.
- Container and Helm artifacts must include immutable version metadata.
- Set `BUILD_CONTAINER=1 REQUIRED_ARTIFACTS=archive,deb,rpm,helm,monitoring,container` when producing an offline operator handoff that includes a Docker image archive.
- All warnings require either remediation or an approved waiver with an expiry date.

## Air-Gapped Bundle

The offline operator bundle must include:

- release packages and container image archive
- Helm chart and default values
- SBOMs, checksums, checksum signature, and checksum public key when applicable
- open-source license, NOTICE, and third-party notices
- upgrade and rollback instructions
- installation, operations, API, and support documentation
- known limitations and accepted-risk notices
