# Support Bundle API Example

These examples show how to trigger and download a support bundle from the control plane.

## Trigger an Export

```bash
curl -X POST http://127.0.0.1:8080/api/v1/control/support \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "manual export",
    "note": "collect bundle before upgrade"
  }'
```

## Check Latest Bundle Metadata

```bash
curl -s http://127.0.0.1:8080/api/v1/control/support | jq '.'
```

## Download the Latest Redacted Bundle

```bash
curl -L http://127.0.0.1:8080/api/v1/control/support/download \
  -o providapt-supportbundle.zip
```

## Query Audit Trail

```bash
curl -s \
  "http://127.0.0.1:8080/api/v1/control/audit?category=admin&source=supportbundle&limit=20" \
  | jq '.'
```
