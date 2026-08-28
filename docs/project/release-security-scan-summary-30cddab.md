# Release Security Scan Summary - 30cddab

Current-commit security scans were rerun for the open-source build.

## Scope

- Commit: `30cddab5d48ae79c5d080ef734f49fe98810d79e`
- Version string: `v1.2.2-305-g30cddab`
- Generated at: `2026-08-28T02:20:34Z`
- Gate status: `pass`
- Scan manifest status: `pass`

## Scanner Results

| Scanner | Status | Exit Code | Duration Seconds |
| --- | --- | ---: | ---: |
| `govulncheck` | `pass` | 0 | 8.342 |
| `grype_source` | `pass` | 0 | 63.515 |
| `trivy_fs` | `pass` | 0 | 197.797 |

## Manifest Coverage

| Report | Status | Size Bytes |
| --- | --- | ---: |
| `govulncheck_text` | `present` | 299 |
| `govulncheck_json` | `present` | 541577 |
| `grype_source` | `present` | 7233 |
| `trivy_fs` | `present` | 23085 |

## Release Follow-Up

This closes the current-commit scan loop. The final release loop remains open
until a final release tag exists. After the tag is cut, rerun the security
scans, regenerate the scan manifest, rebuild final distribution artifacts,
generate checksums/SBOM/signatures, and attach the signed release evidence to
the handoff bundle.
