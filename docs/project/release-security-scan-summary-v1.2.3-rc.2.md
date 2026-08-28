# Release Security Scan Summary - v1.2.3-rc.2

Security scans were rerun for the open-source `v1.2.3-rc.2` release candidate.

## Scope

- Release tag: `v1.2.3-rc.2`
- Commit: `666fee21f1cf4bc665f8e8dbc539fb8e903cf20f`
- Generated at: `2026-08-28T08:33:41Z`
- Gate status: `pass`
- Scan manifest status: `pass`

## Scanner Results

| Scanner | Status | Exit Code | Duration Seconds |
| --- | --- | ---: | ---: |
| `govulncheck` | `pass` | 0 | 6.988 |
| `grype_source` | `pass` | 0 | 5.525 |
| `trivy_fs` | `pass` | 0 | 11.045 |

## Manifest Coverage

| Report | Status | Size Bytes |
| --- | --- | ---: |
| `govulncheck_text` | `present` | 299 |
| `govulncheck_json` | `present` | 541577 |
| `grype_source` | `present` | 7233 |
| `trivy_fs` | `present` | 23090 |

## Notes

- No scanner waiver was used for this candidate scan loop.
- Candidate release artifacts include Ubuntu Linux/BTF-built eBPF objects in the
  archive, Debian, and RPM packages.
- Final `v1.2.3` publication should rerun this same scan loop from the final
  immutable release tag and archive the fresh manifest with the release bundle.
