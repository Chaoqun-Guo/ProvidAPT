# Developer API Reference

**gRPC Interface** | Plugin Development | External System Integration

The machine-readable HTTP contract is available in [openapi.yaml](openapi.yaml).

---

## 1. gRPC Service Definitions

### 1.1 Telemetry Service

```protobuf
// mgmt.proto —Agent-to-Server telemetry
service ProvidAPTTelemetry {
  // Report events from an agent to the central server
  rpc ReportEvents(stream CompressedEvent) returns (ReportAck);
}

message CompressedEvent {
  bytes  payload = 1;         // Zstd-compressed protobuf
  string content_type = 2;    // "proto/edge" | "proto/node" | "proto/event"
  uint64 original_size = 3;   // Pre-compression byte size
  uint64 timestamp_ns = 4;
}

message ReportAck {
  uint32 accepted = 1;        // Number of accepted events
  uint32 throttle_level = 2;  // 0=normal, 1=slow, 2=backpressure
  string message = 3;         // Human-readable status
}
```

### 1.2 Alert Subscription Service

```protobuf
service ProvidAPTAlert {
  // Subscribe to real-time alerts
  rpc Subscribe(AlertFilter) returns (stream Alert);
}

message AlertFilter {
  repeated string severities = 1;  // "CRITICAL", "HIGH", "MEDIUM", "LOW"
  repeated string patterns = 2;    // Pattern IDs to filter
  string host_id = 3;              // Specific host (empty = all)
}

message Alert {
  string id = 1;
  string pattern = 2;
  string severity = 3;
  string headline = 4;
  string reason = 5;
  string alert_node_id = 6;
  uint64 detected_at_ns = 7;
  AlertSubgraph subgraph = 8;
}

message AlertSubgraph {
  repeated Node nodes = 1;
  repeated Edge edges = 2;
  repeated string path_node_ids = 3;
}
```

### 1.3 Graph Query Service

```protobuf
service ProvidAPTGraph {
  // Query the provenance graph
  rpc Query(QueryRequest) returns (QueryResponse);
  // Subscribe to graph changes
  rpc Subscribe(stream GraphSubscription) returns (stream GraphUpdate);
}

message QueryRequest {
  string provql = 1;       // ProvQL query string
  uint32 limit = 2;        // Max results (default 100)
  uint64 offset = 3;       // Pagination offset
}

message QueryResponse {
  repeated Node nodes = 1;
  repeated Edge edges = 2;
  uint32 total_count = 3;
}
```

### 1.4 Management Service

```protobuf
service ProvidAPTManagement {
  // Health check
  rpc Health(Empty) returns (HealthResponse);
  // Get statistics
  rpc Stats(Empty) returns (StatsResponse);
  // Trigger memory forensics on a process
  rpc TriggerMemoryScan(MemoryScanRequest) returns (MemoryScanResponse);
}

message MemoryScanRequest {
  uint32 pid = 1;
  string reason = 2;       // Trigger reason
}

message MemoryScanResponse {
  string status = 1;
  string risk_level = 2;
  repeated string yara_matches = 3;
}
```

---

## 2. Plugin Development Interface

### 2.1 Detection Plugin

```go
// Plugin interface for custom detection patterns
type DetectionPlugin interface {
  // ID returns a unique identifier for this plugin
  ID() string

  // Name returns a human-readable name
  Name() string

  // Evaluate is called during each analyzer scan
  Evaluate(te *TaintEngine) []*Alert
}
```

Example plugin:

```go
package myplugin

type MyDetection struct{}

func (p *MyDetection) ID() string { return "MY_CUSTOM_DETECTION" }
func (p *MyDetection) Name() string { return "Custom Detection Pattern" }

func (p *MyDetection) Evaluate(te *TaintEngine) []*analyzer.Alert {
    var alerts []*analyzer.Alert
    for _, id := range te.TaintedProcesses() {
        tn := te.Tainted(id)
        node := te.nodes[id]
        // Custom logic here
        if tn.Level >= analyzer.TaintHigh {
            alerts = append(alerts, &analyzer.Alert{
                Pattern:     "MY_CUSTOM_DETECTION",
                Severity:    analyzer.SeverityHigh,
                Headline:    "Custom alert: " + node.Label,
                AlertNodeID: id,
            })
        }
    }
    return alerts
}
```

### 2.2 Transport Plugin

```go
// TransportPlugin handles custom event transmission
type TransportPlugin interface {
  // Name returns plugin identifier
  Name() string

  // Send transmits a batch of events
  Send(events []*StreamEvent) error

  // Flush ensures all buffered events are sent
  Flush() error

  // Close cleans up resources
  Close()
}
```

### 2.3 Registration

```go
import "github.com/Chaoqun-Guo/ProvidAPT/pkg/plugin"

func init() {
  plugin.Register(&MyDetection{})
}
```

---

## 3. External System Integration

### 3.0 HTTP API Conventions

Unless an endpoint explicitly documents otherwise, the REST API follows these conventions:

- Authentication: pass `Authorization: Bearer <token>` when API authentication is enabled.
- Content type: send JSON request bodies with `Content-Type: application/json`.
- Errors: failed requests return a non-2xx status and a JSON object containing an `error` field.
- Pagination: list endpoints may include `limit`, `offset`, `since`, or `cursor` query parameters when supported by the endpoint.
- Filtering: fleet, alert, graph, and investigation endpoints support narrow filters such as host, group, tag, severity, node, process ID, time range, and direction where implemented.

Example error response:

```json
{
  "error": "invalid request",
  "details": "missing required action"
}
```

### 3.1 Webhook Output

```json
POST /webhook/providapt HTTP/1.1
Content-Type: application/json

{
  "version": "2.2",
  "timestamp": "2026-05-28T14:23:00Z",
  "alerts": [
    {
      "id": "alert-1716891780",
      "pattern": "MEMORY_ANOMALY",
      "severity": "CRITICAL",
      "headline": "python3 memory anomaly: mprotect RW->X (shellcode injection)",
      "node_id": "p:1337",
      "host_id": "host-web-01",
      "reason": "Process p:1337 (level=CRITICAL depth=5): [mprotect RW->X]",
      "subgraph": {
        "nodes": [...],
        "edges": [...]
      }
    }
  ]
}
```

### 3.2 SIEM Integration

| SIEM | Protocol | Format | Endpoint |
|------|----------|--------|----------|
| Splunk | HTTP Event Collector | JSON | `:8088/services/collector` |
| Elastic | Filebeat/Logstash | JSON Lines | `/var/log/providapt/alerts.jsonl` |
| QRadar | Syslog | LEEF | UDP 514 |
| ArcSight | Syslog | CEF | UDP 514 |

### 3.3 REST API (Test Harness)

The cluster test harness exposes a REST API for external integration. See the CLI guide in `docs/user-guide/cli.md` for operator command examples.
