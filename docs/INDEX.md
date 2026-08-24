# ProvidAPT Documentation

This directory is organized by audience. Start with the section that matches
the work in front of you, then follow the linked runbooks for deeper detail.

## Primary Entry Points

| Section | Audience | Use When |
| --- | --- | --- |
| [Getting Started](getting-started/INDEX.md) | Evaluators, operators, deployment engineers | Installing, evaluating, deploying, or operating ProvidAPT |
| [User Guide](user-guide/INDEX.md) | SecOps and platform operators | Running investigations, RBAC, backup/restore, SIEM, fleet, and day-2 operations |
| [Developer Guide](developer/INDEX.md) | Maintainers and integrators | Extending APIs, schemas, configuration, storage, packaging, testing, and release checks |
| [Architecture](architecture/INDEX.md) | Engineers and reviewers | Understanding provenance capture, graph model, taint scoring, and system design |
| [Compliance](compliance/INDEX.md) | Security, legal, privacy, procurement | Reviewing privacy, retention, threat model, and governance posture |
| [Benchmarks](benchmarks/INDEX.md) | Performance reviewers | Reviewing benchmark methodology and performance evidence |
| [Project Docs](project/INDEX.md) | Release owners and maintainers | Managing release evidence, handoff, approval, sizing, support, and documentation hygiene |

## Current Release and Operations Evidence

- Release checklist: [developer/release-readiness.md](developer/release-readiness.md)
- Release candidate notes: [developer/release-notes-v1.2.3-rc.1.md](developer/release-notes-v1.2.3-rc.1.md)
- Current handoff and remaining work: [project/macbook-ai-development-handoff.md](project/macbook-ai-development-handoff.md)
- Open-source release checklist: [project/open-source-release-checklist.md](project/open-source-release-checklist.md)
- Operations runbook and readiness gates: [user-guide/operations.md](user-guide/operations.md)

## Documentation Maintenance Rules

- Keep operator-facing docs under `getting-started/`, `user-guide/`, or
  `compliance/`.
- Keep developer and API material under `developer/` or `architecture/`.
- Keep release evidence, approval records, and internal handoff material under
  `project/`.
- Avoid adding root-level progress logs; use a project document with a date,
  release line, and clear retention value instead.
