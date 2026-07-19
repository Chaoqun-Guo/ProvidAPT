# Detection Rule Examples

These examples show common rule patterns. Treat them as starting points, not production-ready policy. Validate and tune every rule against customer workloads before publishing.

## Files

| File | Scenario |
| --- | --- |
| `process-exec.yaml` | suspicious shell and downloader execution |
| `file-access.yaml` | sensitive file read and write activity |
| `network-egress.yaml` | outbound connection monitoring |
| `container-escape.yaml` | container boundary and host path access |
| `policy-bundle.yaml` | combined baseline policy bundle outline |

## Publish Workflow

```bash
curl -X POST http://<server>:18080/api/v1/control/policies \
  -H "Content-Type: application/json" \
  -d @policy-update.json
```

Recommended steps:

1. Load rules into a draft policy.
2. Run validation.
3. Review the diff.
4. Request production approval.
5. Publish to the target group.
6. Monitor alert volume and false positives.
