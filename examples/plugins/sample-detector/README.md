# Sample Detector Plugin Fixture

This directory is an open-source fixture for validating the plugin release and
catalog gates. It is not a production plugin bundle.

Run:

```bash
make plugin-example-gates
```

The fixture includes a small bundle payload, a manifest with compatibility and
rollback evidence, and a public test signature file. Production plugin releases
must replace the fixture signature with a customer-approved signing workflow.
