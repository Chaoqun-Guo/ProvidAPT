# ProvidAPT Privacy Notice

**Version 1.0 - Effective 2026-07-28**

ProvidAPT is designed for customer-managed security monitoring. It collects
Linux host telemetry such as process metadata, command lines, file paths,
network endpoints, user and group identifiers, alert workflow metadata, and
operator audit records when those features are enabled.

## Purpose

ProvidAPT uses this data to provide provenance graph construction, threat
detection, investigation, policy management, fleet health monitoring, support
bundle generation, and compliance reporting.

## Customer Control

Customers control where ProvidAPT is deployed, which systems are monitored,
which capture rules are enabled, how long logs are retained, and where exports
or support bundles are delivered.

## Privacy Controls

- TLS is used for control-plane and agent communication when configured.
- Storage encryption and HMAC anonymization are available for sensitive fields.
- Support bundles are redacted by default before handoff.
- Retention controls can limit raw events, alerts, audit logs, reports, and
  support archives.
- Operators can purge local telemetry according to customer policy.

## Sub-processors

ProvidAPT does not require a hosted SaaS control plane by default. Customers are
responsible for evaluating any third-party infrastructure they choose, such as
GitHub, Docker registries, SIEM platforms, ticketing systems, or cloud storage.

## Related Documents

- `DPA.md`
- `EULA.md`
- `SECURITY.md`
- `docs/compliance/security-privacy.md`
- `docs/compliance/privacy-impact.md`

Security and privacy questions can be directed to `security@providapt.io` or
the customer-designated support contact.
