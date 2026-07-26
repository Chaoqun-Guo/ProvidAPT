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

Operational wrapper:

```bash
export PROVIDAPT_SERVER_URL=http://<server>:18080
make ops-siem-verify
```

Set `PROVIDAPT_REQUIRE_SIEM_FORWARDED=1` when the validation must prove that a
collector accepted the event instead of only proving that ProvidAPT queued it.

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

Normalized event records should be mapped before falling back to `raw`:

| ProvidAPT field | Splunk field | Elastic ECS / generic field |
| --- | --- | --- |
| `type` | `event_type` | `event.action` |
| `timestamp_ns` / `timestamp` | `_time` | `@timestamp` |
| `process.pid` | `process_id` | `process.pid` |
| `process.ppid` | `parent_process_id` | `process.parent.pid` |
| `process.comm` | `process_name` | `process.name` |
| `process.exe_path` | `process_path` | `process.executable` |
| `process.cmdline` | `process_command_line` | `process.command_line` |
| `payload.pathname` | `file_path` | `file.path` |
| `payload.inode` | `file_inode` | `file.inode` |
| `payload.dst_addr` | `dest_ip` | `destination.ip` |
| `payload.dst_port` | `dest_port` | `destination.port` |
| `payload.src_addr` | `src_ip` | `source.ip` |
| `payload.src_port` | `src_port` | `source.port` |
| `enrich.agent_id` | `agent_id` | `agent.id` |
| `enrich.hostname` | `host` | `host.name` |
| `raw` | `providapt_raw` | `providapt.raw` |

For alerts, map `rule_id`, `severity`, `message`, `status`, `alert_id`, and
`workflow_state` alongside the related event fields. Keep alert and event
indices separate when high-volume capture is enabled.

## Troubleshooting

- verify token and endpoint reachability
- lower `siem.min_severity` during validation
- inspect `siem.outbox_dir` for queued events
- confirm proxy and firewall rules
- use `file://` delivery first when isolating formatting from network issues
- run `make ops-siem-verify` after every endpoint, token, firewall, or proxy change
