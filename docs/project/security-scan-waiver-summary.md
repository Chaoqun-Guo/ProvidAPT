# Security Scan and Waiver Summary

This summary supports local release-blocking closure for controlled release-candidate handoff. The exact release version and commit are recorded by `dist/release-readiness.md` and `build/release-gate-status.json` when release artifacts are generated.

## Evidence

- govulncheck text evidence: `build/security/govulncheck.txt`
- govulncheck JSON evidence: `build/security/govulncheck.json`
- Waiver record: `build/release-waivers.json`

## Result

- govulncheck evidence reports no reachable vulnerabilities in the captured scan output.
- Grype source scan evidence is waived for this local release-blocking closure.
- Trivy filesystem scan evidence is waived for this local release-blocking closure.

## Constraints

This evidence supports controlled release-candidate handoff only. Run Grype and Trivy in approved CI or security infrastructure before unrestricted public release.
