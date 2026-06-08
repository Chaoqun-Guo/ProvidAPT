# Release Readiness Checklist

This checklist is for the final review before tagging a ProvidAPT product release.

## 1. Build & Validation

- `make v1-ebpf`
- `make v1-userspace`
- `go test ./...` or the scoped package set used in CI
- `GOOS=linux go test -c ./cmd/agent/daemon`
- Run `sudo make loader-smoke` on a Linux host when loader changes are included

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

## 6. Documentation Consistency

- `README.md` navigation includes any new document entry points
- `docs/getting-started/install.md` reflects operator-facing configuration
- `docs/user-guide/cli.md` reflects control-plane endpoints and admin workflows
- `docs/developer/upgrade-guide.md` reflects upgrade / rollback / preflight behavior
- `docs/DOCUMENTATION_AUDIT.md` stays aligned with current document categories
- Release notes / changelog mention customer-visible changes

## 7. Release Decision

Mark the release candidate ready only when:

- build is reproducible
- security validation passes
- upgrade preflight passes
- rollback path is documented
- docs and configuration are consistent
