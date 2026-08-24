# Export Control Review

This document defines the export-control review workflow for international open-source delivery.

## Product Summary

ProvidAPT is a provenance-driven security monitoring and detection platform. It includes cryptographic functionality for TLS, signatures, checksums, trusted-header SSO integration, and integrity verification.

## Review Inputs

| Input | Value |
| --- | --- |
| Release | Recorded in the release evidence file for the target version |
| Destination country / region | Recorded in the release approval packet when distribution is restricted |
| Deploying organization | Recorded in the approval packet when distribution is restricted |
| Deployment model | Public source release or self-hosted Linux deployment |
| Cryptographic features reviewed | TLS, signatures, hashing, checksums, trusted-header SSO integration, and integrity verification |
| Restricted-party screening completed | Required before shipment or production deployment |

## Cryptographic Functions

- TLS for API and telemetry protection.
- Ed25519 or configured signing workflows for release/checksum evidence.
- Hashing for integrity verification and checksums.
- open-source control-plane access with optional trusted-header SSO integration.

## Decision

| Role | Approver | Decision | Date | Notes |
| --- | --- | --- | --- | --- |
| Legal / Trade Compliance | Named approver in approval packet | approve, reject, or conditionally approve | ISO-8601 date | Required for restricted-country, public-sector, or encryption-sensitive distribution |
| Release owner | Named release owner in approval packet | approve or reject | ISO-8601 date | Confirms the release artifact set matches the approved version |

## Rule

Do not ship to a restricted destination or restricted party without Legal / Trade Compliance approval.
