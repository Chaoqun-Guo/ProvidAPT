# Final Release Runbook

This runbook moves a release candidate to a final, immutable open-source release.

## 1. Confirm Release Scope

```bash
git status --short
git log -1 --oneline
```

Requirements:

- working tree is clean
- version number is final
- external approvals are recorded
- waiver decisions are recorded
- operator-facing release notes are complete

## 2. Create the Release Commit

```bash
git add -A
git commit -m "chore: prepare v<version> release"
git push origin master
```

Do not build final artifacts from a dirty working tree. The release evidence must reference the final commit.

## 3. Tag the Release

```bash
git tag -a v<version> -m "ProvidAPT v<version>"
git push origin v<version>
```

## 4. Build Open Source Artifacts

```bash
VERSION=v<version> \
COMMIT=$(git rev-parse --short=12 HEAD) \
BUILD_EBPF=1 \
GO_TAGS=bpf \
RUN_SCANS=1 \
BUILD_CONTAINER=1 \
REQUIRED_ARTIFACTS=archive,deb,rpm,helm,monitoring,container \
make release-open-source
```

Expected artifacts:

- Linux tarball
- Debian package
- RPM package
- Helm chart archive
- monitoring bundle
- container image archive when required
- SPDX and CycloneDX SBOMs
- checksum manifest
- checksum signature
- release readiness report

## 5. Run Security Scans

Required:

```bash
govulncheck -tags=bpf ./...
```

Recommended before unrestricted public release:

```bash
grype dir:.
trivy fs .
```

If a scanner cannot run, record a Security waiver in `docs/project/security-waiver.md`.

## 6. Smoke Test Packages

```bash
PACKAGE_SMOKE_MODE=host make package-smoke-matrix
```

For Docker-backed validation:

```bash
PACKAGE_SMOKE_MODE=docker make package-smoke-matrix
```

## 7. Verify Release Readiness

```bash
make github-actions-evidence

# Also archive the final Actions evidence into the release record:
make github-actions-evidence \
  RELEASE_EVIDENCE=docs/project/release-evidence-v<version>.md

make release-gates \
  CI_EVIDENCE=build/ci/github-actions-evidence.json

make artifact-signing-gate

make release-evidence-consistency-gate \
  VERSION=v<version> \
  COMMIT=$(git rev-parse --short HEAD) \
  FULL_COMMIT=$(git rev-parse HEAD)

providaptctl -release-check \
  -release-evidence docs/project/release-evidence-v<version>.md \
  -release-checksums dist/checksums.txt \
  -release-checksums-signature dist/checksums.txt.sig \
  -release-artifacts-dir dist \
  -release-required-artifacts archive,deb,rpm,helm,monitoring \
  -release-sbom dist/sbom.spdx.json,dist/sbom.cdx.json \
  -release-check-out build/release-readiness.md
```

Aggregate release, artifact, package-smoke, operational, ML, legal, and
operator-handoff evidence:

```bash
make operator-release-gate \
  RELEASE_GATES_JSON=build/release-gate-status.json \
  RELEASE_EVIDENCE_CONSISTENCY_GATE=build/release-evidence/release-evidence-consistency-gate.json \
  PACKAGE_SMOKE_DIR=build/package-smoke

make release-blocker-backlog \
  OPERATOR_RELEASE_GATE=build/operator-release/operator-release-gate.json
```

The release evidence consistency gate checks that the dist SBOMs,
`release-readiness.md`, scan manifest, artifact signing gate, release version,
and commit all describe the same release build.

The generated `build/operator-release/operator-release-gate.json` is the
machine-readable final delivery decision. It also consumes the release evidence
consistency gate, so stale or mismatched release metadata blocks final delivery.
`operator-release-gate.md` is the operator-facing blocker list.
`release-blocker-backlog.json` converts each blocked or warning section into an
owner-ready action item.

Release gates require vulnerability scan evidence for the current commit. When
`RUN_SCANS=1 make release-open-source` runs govulncheck, Grype, or Trivy, it
writes `build/security/scan-manifest.json`; stale or missing scan manifests
block final readiness until scans are rerun for the final release commit/tag.
The manifest must use schema `providapt.security_scan_manifest.v1`, record the
final full commit, include `generated_at`, and mark each required scanner report
as `present`.

## 8. Assemble Handoff

Include:

- artifacts from `dist/`
- release readiness report
- vulnerability scan evidence
- package smoke evidence
- release notes
- operator acceptance test
- production readiness checklist
- security waiver if applicable
- checksums and signatures

## 9. Publish

Publish only after:

- final tag is pushed
- release readiness passes
- public release gate passes
- external approvals are signed
- security waivers are closed or approved
- artifacts are uploaded to the approved distribution channel

## 10. Rollback Plan

Before publishing, confirm:

- previous version artifacts are available
- database backup and config backup exist
- rollback owner and decision window are defined
- operator communication template is ready
