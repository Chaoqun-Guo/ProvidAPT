# Onboarding First-Run Fixture

This directory contains open-source-safe check results for exercising the
first-run onboarding bundle locally.

Run:

```bash
make onboarding-example-gate
```

The fixture records synthetic pass results for Tailscale, SSH, API, dashboard,
TLS, secrets, and PostgreSQL checks. Production release evidence must replace
these values with observed results from the target environment.
