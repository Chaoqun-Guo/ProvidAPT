# Splunk HEC Example

## Configuration

```yaml
siem:
  enabled: true
  provider: splunk
  endpoint: https://splunk.example.com:8088/services/collector
  token: env:PROVIDAPT_SIEM_TOKEN
  index: providapt
  source_type: providapt:audit
  format: json
  min_severity: WARNING
  outbox_dir: /var/log/providapt/siem-outbox
  flush_interval: 30s
```

## Test

```bash
export PROVIDAPT_SIEM_TOKEN=replace-with-splunk-hec-token
curl -X POST http://localhost:18080/api/v1/control/compliance \
  -H "Content-Type: application/json" \
  -d '{"action":"test_siem"}'
```

## Splunk Search

```text
index=providapt sourcetype=providapt:audit
```
