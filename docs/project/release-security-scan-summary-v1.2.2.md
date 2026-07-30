# Release Security Scan Summary - v1.2.2

Date: 2026-07-17
Commit: `27ecd239`

## Tools

| Scope | Tool | Version / Image | Result |
| --- | --- | --- | --- |
| SBOM | Syft | `anchore/syft:v1.38.0` | Generated SPDX and CycloneDX SBOMs in `dist/` |
| Source-only | Grype | `anchore/grype:v0.104.0` | 0 vulnerability matches |
| Source-only | Trivy | `aquasec/trivy:0.67.2` | 0 vulnerability findings, 0 secret findings |

## Notes

- Source-only scans exclude generated `dist/`, `build/`, `.git/`, and local `.tmp-*` cache directories and are the commercial source gate.
- `golang.org/x/net` and `golang.org/x/text` were upgraded to address the source dependency findings reported before this pass.
- `dist/release-readiness.md` reports `commercial ready: 16 passed, 0 warnings, 0 waived, 0 failed`.
