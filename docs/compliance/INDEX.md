# Compliance And Security

This section describes ProvidAPT security, privacy, audit, and data-processing controls.

## Documents

| Document | Description |
| --- | --- |
| [security-privacy.md](security-privacy.md) | Redaction, privacy, and security design |
| [data-retention.md](data-retention.md) | Data classes, retention windows, deletion, export, and legal hold guidance |
| [threat-model.md](threat-model.md) | Assets, trust boundaries, threats, and compensating controls |
| [privacy-impact.md](privacy-impact.md) | Privacy impact assessment for collected metadata and operator responsibilities |

## Design Principles

- Data minimization: collect only fields required for provenance and detection.
- Configurable redaction: protect sensitive paths, addresses, tokens, and identifiers.
- Tamper-evident audit: retain integrity-verifiable audit evidence.
- Access control: protect the management plane with TLS, trusted-header SSO integration, RBAC, and audit trails.

## Configuration

Security and audit behavior is primarily configured through `/etc/providapt/providapt.toml`.
Deployment details are documented in `docs/getting-started/deployment.md`.
