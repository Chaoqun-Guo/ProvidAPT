# Privacy Impact Assessment

ProvidAPT records provenance metadata for security detection and incident response. This document helps privacy and legal reviewers understand collected fields, protections, and customer responsibilities.

## Data Collected

| Category | Examples | Purpose |
| --- | --- | --- |
| process metadata | PID, command name, parent process, executable path | provenance graph and detection |
| file metadata | path, operation, timestamps | sensitive access and lineage detection |
| network metadata | address, port, protocol | egress and lateral movement detection |
| host metadata | hostname, kernel, OS, agent ID | fleet monitoring and troubleshooting |
| operator metadata | API actor, role, tenant, action | audit and compliance |

ProvidAPT is designed to collect metadata, not file contents. Customer configuration determines redaction, retention, and export destinations.

## Privacy Controls

- configurable path and value masking
- optional tenant scoping
- RBAC for dashboard and API access
- support bundle redaction
- retention controls
- SIEM delivery filtering by severity

## Customer Responsibilities

- approve monitored hosts and data categories
- configure redaction for sensitive paths and identifiers
- set retention based on policy and law
- protect SIEM tokens, TLS keys, and encryption material
- review support bundles before external sharing
- document employee notice or consent requirements where applicable

## Review Questions

- Are monitored systems allowed to collect process and path metadata?
- Which paths or users require masking?
- Which teams may view raw provenance traces?
- Is cross-border SIEM delivery permitted?
- What retention period applies to investigation evidence?
