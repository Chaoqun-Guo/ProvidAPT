# Release Readiness Checklist

This checklist is for the final review before tagging a ProvidAPT product release.

## 1. Build & Validation

- `make build-ebpf`
- `make build-userspace`
- `make release-commercial`
- `make package-smoke-matrix`
- `PACKAGE_SMOKE_MODE=host make package-smoke-matrix` on disposable Linux validation hosts when Docker registry access is unavailable
- `go test ./...` or the scoped package set used in CI
- `GOOS=linux go test -c ./cmd/agent/daemon`
- Run `sudo make loader-smoke` on a Linux host when loader changes are included
- Save validation evidence under the release record:
  - commit SHA, release tag, build host, kernel version, Go version
  - build logs for eBPF and userspace artifacts
  - test, vet, lint, coverage, and loader-smoke output
  - package install/uninstall logs for `.deb`, `.rpm`, tarball, Docker, and Helm when applicable

## 2. Control Plane Validation

- `GET /api/v1/control/support`
- `GET /api/v1/control/license`
- `GET /api/v1/control/upgrade`
- Verify RBAC paths for `admin`, `analyst`, `auditor`
- Verify Dashboard cards load without API errors

## 3. License Validation Checks

- Confirm `license.path` points to the intended release license fixture or customer license
- Validate expiry / grace period behavior
- Validate revoked license behavior
- If remote revocation is enabled:
  - verify `license.revocation_url`
  - verify `license.revocation_cache`
  - verify `license.revocation_sig_url`
  - verify `license.revocation_sig_cache`
  - confirm `revocation_verified` is `true`
- Validate signature verification using either:
  - `license.public_key_path` for `Ed25519`
  - `license.signing_key` for HMAC compatibility mode

## 4. Upgrade Preflight Checks

- Verify `upgrade.download_url`, `upgrade.package_path`, `upgrade.signature_path`
- Verify `upgrade.expected_sha256`
- Verify package signature with:
  - `upgrade.public_key_path` for `Ed25519`
  - `upgrade.signing_key` for HMAC compatibility mode
- Confirm `download` action succeeds
- Confirm `preflight` action returns `preflight_ready=true`
- Confirm rollback plan is present before release notes are approved

## 5. Operational Safety

- Confirm support bundle redaction is enabled by default
- Confirm archive retention settings are appropriate
- Confirm audit logging is enabled and captures support/license/upgrade actions
- Review any new environment variables added in this release
- Confirm default deployment does not expose unauthenticated control-plane endpoints
- Confirm privileged container, host path, BPF, and cgroup permissions are documented and minimized
- Confirm failure modes are operator-safe:
  - eBPF attach failure falls back or exits with clear diagnostics
  - storage corruption or disk-full errors are visible in logs and metrics
  - license or upgrade service outage does not break local detection unexpectedly

## 6. Supply Chain & Artifact Integrity

- Run `make release-gates` before final review. It writes `build/release-gate-status.md` and `build/release-gate-status.json` with CI, scanner availability, scanner evidence, approval, and artifact status.
- When GitHub Actions or scanner evidence is collected outside the local
  workstation, pass it explicitly:

  ```bash
  python3 scripts/release/release_gate_status.py \
    --ci-evidence docs/project/github-actions-final.md \
    --waiver build/release-waivers.json
  ```

  Structured waivers use `{"waivers":[{"gate":"grype_evidence","status":"approved_with_risk"}]}`.
  Markdown waiver files are accepted only when they mention the gate and an
  approval/accepted-risk decision.
- Confirm `checksums.txt` is generated and signed
- Confirm release binaries embed version, commit, and build date
- Run `providaptctl -release-check -config <release-config> -release-evidence docs/project/release-evidence-v1.2.3-rc.1.md -release-waivers build/release-waivers.json -release-checksums dist/checksums.txt -release-checksums-signature dist/checksums.txt.sig -release-artifacts-dir dist -release-handoff build/handoff/providapt-v1.2.3-rc.1-handoff.zip -release-required-artifacts archive,deb,rpm,helm,monitoring -release-sbom dist/sbom.spdx.json,dist/sbom.cdx.json -release-check-out build/release-readiness.md`
- If a commercial warning is intentionally accepted, capture it in `build/release-waivers.json` with `check`, `reason`, `approved_by`, and optional `expires`
- Confirm `dist/checksums.txt` contains one SHA-256 entry per published release artifact
- Confirm the checksum manifest includes the required commercial artifact types: `archive`, `deb`, `rpm`, `helm`, and `monitoring`
- Confirm every artifact listed in `dist/checksums.txt` exists under `dist/` and matches its SHA-256 digest
- Confirm `dist/checksums.txt.sig` or equivalent detached signature evidence is captured; `providapt-sign` Ed25519 bundles, GPG armored signatures, Minisign signatures, and Cosign bundle evidence are recognized in release reports
- When using `providapt-sign`, publish `dist/checksums.txt.pub` with the release handoff package and keep the private key under customer-approved key custody
- Confirm SBOM artifacts are generated in SPDX and CycloneDX JSON formats
- Confirm container image labels include source, version, and revision
- Confirm release artifacts can be verified from a clean machine
- Confirm dependency and container vulnerability scan results are captured or explicitly waived
- Confirm release tooling versions are pinned in CI and release logs, including `SYFT_IMAGE`, `GRYPE_IMAGE`, `TRIVY_IMAGE`, and the GitHub Action `SYFT_VERSION`
- Run the workflow-dispatch `commercial release and package smoke` CI job before customer handoff
- Confirm required commercial artifacts match `docs/project/release-artifact-matrix.md`
- Confirm air-gapped delivery bundle includes:
  - binaries and packages
  - Helm chart and default values
  - SBOM and checksums
  - offline license and upgrade instructions
  - operator docs needed without internet access

## 7. Commercial Readiness

- Confirm customer-facing contacts are valid:
  - `security@providapt.io`
  - `legal@providapt.io`
  - `dpo@providapt.io`
  - support intake address or portal
- Confirm SLA, support severity levels, and escalation paths are documented
- Confirm support readiness matches `docs/project/support-sla.md`
- Confirm EULA, DPA, privacy posture, and third-party notices are reviewed for the release
- Confirm onboarding material exists for:
  - trial / evaluation install
  - production deployment
  - first alert investigation
  - support bundle export
  - upgrade and rollback
- Confirm sales engineering material is ready:
  - sizing guidance
  - demo scenario
  - POC success criteria
  - known limitations and supported platforms
- Confirm customer handoff material matches `docs/project/customer-handoff.md`
- Pass `-release-handoff` when a candidate handoff directory or zip exists, so stale approval text or mismatched commit evidence is caught before delivery.
- Confirm final release approvals are captured in `docs/project/commercial-approval-record.md`

## 8. Documentation Consistency

- `README.md` navigation includes any new document entry points
- `docs/getting-started/install.md` reflects operator-facing configuration
- `docs/user-guide/cli.md` reflects control-plane endpoints and admin workflows
- `docs/developer/upgrade-guide.md` reflects upgrade / rollback / preflight behavior
- `docs/project/documentation-audit.md` stays aligned with current document categories
- Release notes / changelog mention customer-visible changes

## 9. Release Decision

Mark the release candidate ready only when:

- build is reproducible
- security validation passes
- upgrade preflight passes
- rollback path is documented
- docs and configuration are consistent
- commercial, legal, and support owners have approved the release
