# Compliance & Security

This section describes ProvidAPT's design and practices in data security, privacy compliance, and audit integrity.

## Documents

| Document | Description |
| --- | --- |
| [security-privacy.md](security-privacy.md) | Data masking: sensitive field identification, masking strategies, configuration methods |

## Compliance Design Principles

- **Data Minimization**: Collects only event attributes necessary for provenance, supports on-demand filtering
- **Configurable Masking**: File paths, network addresses and other sensitive fields support regex matching and replacement
- **Tamper-Evident Audit**: Event logs chained via hash linking, supports integrity verification
- **Access Control**: gRPC API supports mTLS authentication and RBAC permission management

## Related Configuration

Masking rules and audit policies are configured via `/etc/providapt/providapt.toml`. See the security section in the [deployment guide](../getting-started/deployment.md) for details.
