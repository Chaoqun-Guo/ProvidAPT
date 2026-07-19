# Elastic Bulk Example

## Configuration

```yaml
siem:
  enabled: true
  provider: elastic
  endpoint: https://elastic.example.com:9200/_bulk
  token: env:PROVIDAPT_SIEM_TOKEN
  index: providapt-alerts
  source_type: providapt:audit
  format: json
  min_severity: WARNING
  outbox_dir: /var/log/providapt/siem-outbox
  flush_interval: 30s
```

## Test

```bash
export PROVIDAPT_SIEM_TOKEN=replace-with-elastic-token
curl -X POST http://localhost:18080/api/v1/control/compliance \
  -H "Content-Type: application/json" \
  -d '{"action":"test_siem"}'
```

## Query

```bash
curl -H "Authorization: ApiKey $ELASTIC_API_KEY" \
  "https://elastic.example.com:9200/providapt-alerts/_search?q=agent_id:*"
```
