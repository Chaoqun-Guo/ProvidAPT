# SIEM Integration

ProvidAPT can deliver security and audit events to file, HTTP, TCP, UDP, Splunk HEC, or Elastic Bulk compatible destinations.

## Configuration

```yaml
siem:
  enabled: true
  provider: splunk
  endpoint: https://splunk-hec.example.com:8088/services/collector
  token: env:PROVIDAPT_SIEM_TOKEN
  index: providapt
  source_type: providapt:audit
  format: json
  min_severity: WARNING
  outbox_dir: /var/log/providapt/siem-outbox
  flush_interval: 30s
```

## Providers

| Provider | Endpoint Example | Notes |
| --- | --- | --- |
| generic | `https://siem.example.com/events` | JSON or CEF payload over HTTP |
| splunk | `https://splunk:8088/services/collector` | Splunk HEC token required |
| elastic | `https://elastic:9200/_bulk` | Bulk payload format |
| file | `file:///var/log/providapt/siem.ndjson` | useful for validation and air-gapped review |
| tcp / udp | `tcp://siem.example.com:514` | network transport for compatible collectors |

## Test Delivery

```bash
curl -X POST http://<server>:18080/api/v1/control/compliance \
  -H "Content-Type: application/json" \
  -d '{"action":"test_siem"}'
```

Check status:

```bash
curl -s http://<server>:18080/api/v1/control/compliance
find /var/log/providapt/siem-outbox -type f | head
```

## Field Mapping

Common fields:

| Field | Meaning |
| --- | --- |
| `timestamp` | event or audit timestamp |
| `severity` | INFO, WARNING, HIGH, or CRITICAL depending on source |
| `agent_id` | reporting host identity |
| `tenant` | tenant or fleet group when available |
| `alert_id` | alert workflow identifier |
| `actor` | API or operator identity for control-plane actions |
| `action` | control-plane or alert workflow action |
| `trace_id` | investigation or correlation identifier when available |

## Troubleshooting

- verify token and endpoint reachability
- lower `siem.min_severity` during validation
- inspect `siem.outbox_dir` for queued events
- confirm proxy and firewall rules
- use `file://` delivery first when isolating formatting from network issues
