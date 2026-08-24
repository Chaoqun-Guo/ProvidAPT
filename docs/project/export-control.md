# Export Control Review

This document defines the export-control review workflow for international open-source delivery.

## Product Summary

ProvidAPT is a provenance-driven security monitoring and detection platform. It includes cryptographic functionality for TLS, signatures, checksums, authentication, and integrity verification.

## Review Inputs

| Input | Value |
| --- | --- |
| Release | Recorded in the release evidence file for the target version |
| Destination country / region | Recorded in the customer approval packet |
| Customer | Recorded in the customer approval packet |
| Deployment model | SaaS, managed appliance, or customer-managed Linux deployment |
| Cryptographic features reviewed | TLS, signatures, hashing, checksums, authentication, and integrity verification |
| Restricted-party screening completed | Required before shipment or production deployment |

## Cryptographic Functions

- TLS for API and telemetry protection.
- Ed25519 or configured signing workflows for release/checksum/license evidence.
- Hashing for integrity verification and checksums.
- open-source control-plane access with optional trusted-header SSO integration.

## Decision

| Role | Approver | Decision | Date | Notes |
| --- | --- | --- | --- | --- |
| Legal / Trade Compliance | Named approver in approval packet | approve, reject, or conditionally approve | ISO-8601 date | Required for restricted-country, public-sector, reseller, and encryption-sensitive deals |
| Release owner | Named release owner in approval packet | approve or reject | ISO-8601 date | Confirms the release artifact set matches the approved version |

## Rule

Do not ship to a restricted destination or restricted party without Legal / Trade Compliance approval.
