# Onboarding First-Run Fixture

This directory contains open-source-safe check results for exercising the
first-run onboarding bundle locally.

Run:

```bash
make onboarding-example-gate
```

The fixture records synthetic pass results for Tailscale, SSH, API, dashboard,
TLS, disk, permissions, secrets, and PostgreSQL checks. Production release
evidence must replace these values with observed results from the target
environment.

For a real local or Tailscale-backed first run, point the generated checks at
the control-plane URL:

```bash
make onboarding-wizard \
  PROVIDAPT_SERVER_URL=http://vm-ubuntu-master:18080 \
  ONBOARDING_VM_HOSTS="ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave" \
  RUN_ONBOARDING_CHECKS=1
```

`PROVIDAPT_SERVER_URL` is written into the onboarding manifest and used by the
API, dashboard, visual-regression, and operator-flow commands. Use
`POLICY_ENDPOINT=...` only when agents should poll policy from a different
endpoint than the dashboard/API URL.
