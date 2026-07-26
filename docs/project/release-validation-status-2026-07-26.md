# Release Validation Status - 2026-07-26

This record captures the validation state for the current `master` workspace.

## Scope

| Field | Value |
| --- | --- |
| Commit | `9cdf515e88d7ed28eeaa429a3cd7d7e0354673ad` |
| Branch | `master` |
| Release line | `v1.2.3-rc.1` |
| Validation host | local Windows workstation |

## Completed Checks

| Check | Command | Result |
| --- | --- | --- |
| Release-scoped Go tests | `go test ./pkg/api ./pkg/config ./internal/storage/format ./pkg/releasecheck ./pkg/controlplaneha ./cmd/cli/providaptctl ./cmd/cli/providapt-sign` | PASS |
| Docker daemon availability | `docker version --format '{{.Server.Version}}'` | PASS: Docker Server `29.6.2` |
| GitHub Actions access | `gh run list --limit 10 --json ...` | BLOCKED: `gh` is not authenticated |
| Local scanner availability | `govulncheck`, `grype`, `trivy` lookup | BLOCKED: tools are not installed locally |
| Containerized Grype/Trivy scan | Docker scanner images | BLOCKED: requires explicit approval to mount repository into third-party scanner containers |

## Release Gate Status

| Gate | Status | Next Action |
| --- | --- | --- |
| GitHub Actions | blocked | Authenticate `gh` or review Actions in GitHub UI |
| Grype source scan | blocked | Install `grype` locally or approve `anchore/grype:v0.104.0` container scan |
| Trivy filesystem scan | blocked | Install `trivy` locally or approve `aquasec/trivy:0.67.2` container scan |
| External approvals | blocked | Record Product, Security, Legal, Support, and Sales Engineering decisions |
| Final release artifacts | blocked | Rebuild from the final release tag after approvals and scanner closure |

## Notes

- The current `dist/` artifacts remain the previously generated `v1.2.3-rc.1` candidate artifacts. They should not be treated as final artifacts for commit `9cdf515e88d7ed28eeaa429a3cd7d7e0354673ad` until the release build is rerun.
- The local Go command reported a Go telemetry token write warning under the user profile, but the selected package tests completed successfully.
