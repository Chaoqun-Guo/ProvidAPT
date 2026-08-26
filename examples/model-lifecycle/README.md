# Model Lifecycle Fixture

This directory contains open-source-safe fixture evidence for exercising the
model lifecycle promotion gate. The files are synthetic and are not production
model approval records.

Run:

```bash
make model-lifecycle-example-gate
```

The generated gate output demonstrates the required promotion packet shape:
closed-loop readiness, deploy-gate pass status, stable drift evidence, reviewed
feedback label diversity, a long enough baseline window, multi-window
long-term baseline evidence, and named approvals.

The `baseline.json` fixture models the long-running baseline report that should
eventually come from real analyst feedback and noisy-host soak data. Keep
production baseline files with the model artifact and release evidence bundle.
