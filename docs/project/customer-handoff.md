# Customer Handoff Checklist

This checklist turns a release candidate into a repeatable customer delivery package.

## Pre-Handoff

| Item | Owner | Status |
| --- | --- | --- |
| Customer scope and success criteria confirmed | Product / SE | record before handoff |
| Supported platforms and kernel prerequisites reviewed | Engineering / SE | record before handoff |
| License entitlement and expiry confirmed | Sales / Legal | record before handoff |
| Deployment topology selected | SE / Customer | record before handoff |
| Data handling and privacy requirements reviewed | Legal / Security | record before handoff |

## Delivery Package

- installation package or air-gapped bundle
- release notes and known limitations
- license file or offline activation instructions
- installation and upgrade guide
- rollback and backup procedures
- first-alert investigation workflow
- support bundle export instructions
- SLA and support contact information

## POC Success Criteria

| Area | Example Criterion |
| --- | --- |
| Deployment | Agents installed on target Linux distributions without manual source build |
| Visibility | Control plane reports all enrolled agents as healthy |
| Detection | At least one approved detection rule triggers an alert workflow |
| Investigation | Operator can open provenance graph and export investigation report |
| Policy | Operator can edit, validate, publish, and rollback a policy bundle |
| Operations | Support bundle, backup, audit export, and compliance report work |
| Performance | CPU, memory, event throughput, and storage usage stay within agreed bounds |

## Production Handoff

1. Confirm release artifact checksums and signatures.
2. Import or validate customer license.
3. Install control plane and agents.
4. Confirm fleet health, environment details, and policy status.
5. Configure SIEM or notification integration.
6. Run first-alert investigation exercise.
7. Export release and compliance evidence.
8. Record accepted limitations and support contacts.

## Signoff

| Area | Approver | Decision | Date |
| --- | --- | --- | --- |
| Customer owner | named in handoff packet | approve or reject | ISO-8601 date |
| Sales engineering | named in handoff packet | approve or reject | ISO-8601 date |
| Support | named in handoff packet | approve or reject | ISO-8601 date |
| Security | named in handoff packet | approve or reject | ISO-8601 date |
| Product | named in handoff packet | approve or reject | ISO-8601 date |
