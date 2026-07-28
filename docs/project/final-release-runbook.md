# Final Release Runbook

This runbook moves a release candidate to a final, immutable commercial release.

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
- customer-facing release notes are complete

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

## 4. Build Commercial Artifacts

```bash
VERSION=v<version> \
COMMIT=$(git rev-parse --short=12 HEAD) \
BUILD_EBPF=1 \
GO_TAGS=bpf \
RUN_SCANS=1 \
BUILD_CONTAINER=1 \
REQUIRED_ARTIFACTS=archive,deb,rpm,helm,monitoring,container \
make release-commercial
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

make release-gates \
  CI_EVIDENCE=build/ci/github-actions-evidence.json

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
customer-handoff evidence:

```bash
make customer-release-gate \
  RELEASE_GATES_JSON=build/release-gate-status.json \
  PACKAGE_SMOKE_DIR=build/package-smoke

make release-blocker-backlog \
  CUSTOMER_RELEASE_GATE=build/customer-release/customer-release-gate.json
```

The generated `build/customer-release/customer-release-gate.json` is the
machine-readable final delivery decision. `customer-release-gate.md` is the
operator-facing blocker list. `release-blocker-backlog.json` converts each
blocked or warning section into an owner-ready action item.

## 8. Assemble Handoff

Include:

- artifacts from `dist/`
- release readiness report
- vulnerability scan evidence
- package smoke evidence
- release notes
- customer acceptance test
- production readiness checklist
- security waiver if applicable
- checksums and signatures

## 9. Publish

Publish only after:

- final tag is pushed
- release readiness passes
- customer release gate passes
- external approvals are signed
- security waivers are closed or approved
- artifacts are uploaded to the approved distribution channel

## 10. Rollback Plan

Before publishing, confirm:

- previous version artifacts are available
- database backup and config backup exist
- rollback owner and decision window are defined
- customer communication template is ready
