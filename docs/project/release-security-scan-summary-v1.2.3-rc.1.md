# Release Security Scan Summary - v1.2.3-rc.1

Date: 2026-07-19
Version: `v1.2.3-rc.1`
Commit evidence: `6e459ff0-worktree`

## Tools

| Scope | Tool | Version / Image | Result |
| --- | --- | --- | --- |
| SBOM | Syft fallback | Go module inventory fallback | Generated SPDX and CycloneDX SBOMs in `dist/` |
| Go reachable code | govulncheck | `govulncheck@v1.6.0`, Go `1.25.12`, DB updated `2026-07-08` | 0 reachable vulnerabilities |
| Source-only | Grype | `anchore/grype:v0.104.0` | Not completed: Docker registry / Docker socket access was unavailable in the Linux rerun environment |
| Source-only | Trivy | `aquasec/trivy:0.67.2` | Not completed: Docker registry / Docker socket access was unavailable in the Linux rerun environment |

## Evidence

- `build/security/govulncheck.txt`
- `build/security/govulncheck.json`
- `build/security/govulncheck-version.txt`
- `dist/release-readiness.md`
- `build/package-smoke/`

## Notes

- govulncheck initially reported reachable Go standard-library vulnerabilities when the release was built with Go `1.25.0`.
- The build toolchain and `go.mod` were upgraded to Go `1.25.12`.
- The Go `1.25.12` rerun reported `No vulnerabilities found`.
- Grype/Trivy remain recommended before unrestricted public publication, or Security must explicitly approve this govulncheck-only evidence for the target delivery.
