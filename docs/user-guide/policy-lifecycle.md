# Policy Lifecycle

This guide covers policy draft, validation, diff, approval, publish, rollout, and rollback.

## Lifecycle

```text
draft -> validate -> review diff -> request approval -> publish -> monitor rollout -> rollback if needed
```

## Draft and Validate

```bash
curl -X POST http://<server>:18080/api/v1/control/policies \
  -H "Content-Type: application/json" \
  -d '{"action":"validate_sigma","rule_yaml":"title: suspicious command\nlogsource:\n  product: linux"}'
```

## Review Diff

```bash
curl -s http://<server>:18080/api/v1/control/policies
```

Review:

- added, changed, and removed rules
- whitelist changes
- taint source changes
- target group or tag scope
- expected alert volume impact

## Request Approval

```bash
curl -X POST http://<server>:18080/api/v1/control/compliance \
  -H "Content-Type: application/json" \
  -d '{"action":"request_approval","target":"policy.publish","note":"new Linux credential access rules"}'
```

## Publish

```bash
curl -X POST http://<server>:18080/api/v1/control/policies \
  -H "Content-Type: application/json" \
  -d '{"action":"publish","target_group":"prod","note":"approved policy update"}'
```

## Monitor Rollout

```bash
curl -s http://<server>:18080/api/v1/control/policies
curl -s http://<server>:18080/api/v1/control/fleet
```

Confirm:

- target count matches expected agents
- revoked agents are excluded
- quarantined agents do not silently advance
- agents report the desired policy version

## Rollback

```bash
curl -X POST http://<server>:18080/api/v1/control/policies \
  -H "Content-Type: application/json" \
  -d '{"action":"rollback","version":3,"note":"false positive rollback"}'
```

Rollback when alert volume, false positives, or operator impact exceeds the approved threshold.
