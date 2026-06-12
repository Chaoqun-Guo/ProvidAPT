# gRPC API

ProvidAPT exposes a gRPC API on port `50051` (configurable) for programmatic access and SIEM integration.

## Services

### ProvidAPTManagement

| RPC | Type | Description |
|-----|------|-------------|
| `Query` | Unary | Execute ProvQL queries against historical provenance data |
| `WatchAlerts` | Server stream | Stream real-time alerts matching a filter |
| `UpdatePolicy` | Unary | Dynamically update detection/response policies |
| `Check` | Unary | Health check returning daemon status |

### ProvidAPTTelemetry

| RPC | Type | Description |
|-----|------|-------------|
| `ReportEvents` | Client stream | Agents stream compressed provenance events |

## Usage Examples

### Using grpcurl

```bash
# List available services
grpcurl -plaintext localhost:50051 list

# Health check
grpcurl -plaintext localhost:50051 providapt.mgmt.ProvidAPTManagement.Check

# Stream alerts (long-lived connection)
grpcurl -plaintext -d '{"min_severity": "HIGH"}' \
  localhost:50051 providapt.mgmt.ProvidAPTManagement.WatchAlerts
```

### Using grpc-go (Go client)

```go
import pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"

conn, _ := grpc.Dial("localhost:50051", grpc.WithInsecure())
defer conn.Close()

client := pb.NewProvidAPTManagementClient(conn)
health, _ := client.Check(context.Background(), &pb.HealthCheck{})
fmt.Println("Status:", health.Status)
```

## Proto Definitions

Service and message definitions are in `pkg/api/proto/mgmt/mgmt.proto`.

## TLS

For production, configure mTLS in `providapt.toml`:

```toml
[tls]
enable = true
cert_file = "/etc/providapt/certs/server.crt"
key_file = "/etc/providapt/certs/server.key"
ca_file = "/etc/providapt/certs/ca.crt"
```
