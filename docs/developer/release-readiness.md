# Release Readiness Checklist

This checklist is for the final review before tagging a ProvidAPT product release.

## 1. Build & Validation

- `make build-ebpf`
- `make build-userspace`
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

- Confirm `checksums.txt` is generated and signed
- Confirm release binaries embed version, commit, and build date
- Run `providaptctl -release-check -config <release-config> -release-evidence docs/project/release-evidence-v1.2.2.md`
- Confirm SBOM artifacts are generated in SPDX and CycloneDX formats
- Confirm container image labels include source, version, and revision
- Confirm release artifacts can be verified from a clean machine
- Confirm dependency and container vulnerability scan results are captured or explicitly waived
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
