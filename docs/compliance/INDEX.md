# Compliance And Security

This section describes ProvidAPT security, privacy, audit, and data-processing controls.

## Documents

| Document | Description |
| --- | --- |
| [security-privacy.md](security-privacy.md) | Redaction, privacy, and security design |

## Design Principles

- Data minimization: collect only fields required for provenance and detection.
- Configurable redaction: protect sensitive paths, addresses, tokens, and identifiers.
- Tamper-evident audit: retain integrity-verifiable audit evidence.
- Access control: protect the management plane with authentication, RBAC, and audit trails.

## Configuration

Security and audit behavior is primarily configured through `/etc/providapt/providapt.toml`.
Deployment details are documented in `docs/getting-started/deployment.md`.
