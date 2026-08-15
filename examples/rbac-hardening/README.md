# RBAC Hardening Fixture

This directory contains open-source-safe fixture evidence for exercising RBAC,
tenant isolation, approval workflow, audit export, role review, and customer
environment certification gates.

Run:

```bash
make rbac-hardening-example-gate
```

The fixture keys are public test strings and must not be used as deployment
credentials. Production release evidence must replace these files with real
tenant-scoped configuration, audit exports, and role review approvals.
