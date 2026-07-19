# Production Readiness Checklist

Use this checklist before deploying ProvidAPT into a production customer environment.

## Platform

- Kernel version, BTF, and BPF LSM support are verified.
- Supported distribution and package type are selected.
- CPU, memory, disk, and PostgreSQL capacity match the sizing guide.
- NTP or another clock synchronization service is active on all nodes.

## Security

- Authentication is enabled.
- TLS is enabled for operator and agent/server traffic.
- CORS origins are restricted to approved consoles.
- API keys, SIEM tokens, license files, encryption keys, and TLS private keys are stored in customer-approved secret management.
- Sample values from `examples/config/providapt.production.yaml` are replaced with customer-approved settings.
- Audit retention matches customer compliance requirements.

## Storage and Retention

- PostgreSQL is configured for production control-plane storage.
- Local event and support-bundle paths have sufficient capacity.
- Backups are configured and restore has been tested.
- Retention windows for raw events, alerts, audit records, and support bundles are approved.

## Operations

- systemd, Docker Compose, or Helm deployment path is documented.
- Start, stop, restart, upgrade, rollback, backup, and uninstall procedures are tested.
- Monitoring and alerting are connected to the customer's observability platform.
- SIEM delivery is tested or outbox retry behavior is accepted.
- Support bundle collection is verified.

## Release and Approval

- Release evidence references the final clean commit and version.
- SBOMs, checksums, and signatures are present.
- Vulnerability scan evidence is approved by Security.
- Product, Legal, Support, and Sales Engineering approvals are recorded.
- Customer acceptance test is complete.

## Rollback

- Previous package or image is available.
- Configuration backup exists.
- Database backup exists when schema or retention settings changed.
- Rollback command and owner are documented.
- Rollback success criteria are defined.
