# Release Security Scan Summary - v1.2.3

Security scans were rerun for the final open-source `v1.2.3` release tag.

## Release Identity

| Field | Value |
| --- | --- |
| Release tag | `v1.2.3` |
| Commit SHA | `0ba72be5db90e9877e9025cb6d7774e4095c468f` |
| Scan generated at | `2026-09-02T06:35:58Z` |
| Scan manifest | `build/security-final/scan-manifest.json` |

## Scanner Results

| Scanner | Status | Findings / Blockers | Duration Seconds |
| --- | --- | ---: | ---: |
| `govulncheck` | `pass` | 0 | 8.625 |
| `grype_source` | `pass` | 0 | 86.012 |
| `trivy_fs` | `pass` | 0 | 39.430 |

## Evidence Files

| Report | Status | Size |
| --- | --- | ---: |
| `govulncheck_text` | `present` | 299 |
| `govulncheck_json` | `present` | 541577 |
| `grype_source` | `present` | 7233 |
| `trivy_fs` | `present` | 25891 |

## Notes

- No scanner waiver was used for this final scan loop.
- The scan was rerun after final artifact refresh and RPM inclusion.
- The release security local gate reported `status=pass`, `manifest=pass`, and `blocked=0`.
