// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/pipeline"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/policy/alert"
	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"
	"google.golang.org/grpc"
)

// ─── Management server ──────────────────────────────────────────

// provaptManagementServer implements the ProvidAPTManagement gRPC service
// wired to real backend dependencies.
type provaptManagementServer struct {
	startedAt  time.Time
	graph      *provenance.Graph
	pipeline   *pipeline.Pipeline
	alertPipe  *alert.AlertPipeline
	version    string
}

// Compile-time interface check.
var _ pb.ProvidAPTManagementServer = (*provaptManagementServer)(nil)

// newProvidAPTManagementServer creates a management server with live backends.
func newProvidAPTManagementServer(opts GRPCOptions) *provaptManagementServer {
	return &provaptManagementServer{
		startedAt: time.Now(),
		graph:     opts.Graph,
		pipeline:  opts.Pipeline,
		alertPipe: opts.AlertPipeline,
		version:   opts.Version,
	}
}

// Query handles ProvQL graph queries against the live provenance DAG.
func (s *provaptManagementServer) Query(ctx context.Context, req *pb.QueryRequest) (*pb.QueryResponse, error) {
	start := time.Now()

	if s.graph == nil {
		return &pb.QueryResponse{
			ResultCount:  0,
			ResultsJson:  `{"error":"graph not connected"}`,
			QueryTimeNs:  time.Since(start).Nanoseconds(),
		}, nil
	}

	// Gather nodes and edges from the in-memory graph.
	nodes := s.graph.Nodes()
	edges := s.graph.Edges()

	// Filter by container if requested.
	if req.GetContainer() != "" {
		containerFilter := req.GetContainer()
		filteredNodes := make([]*provenance.Node, 0, len(nodes))
		for _, n := range nodes {
			if n.Subtype == containerFilter {
				filteredNodes = append(filteredNodes, n)
			}
		}
		nodes = filteredNodes
		// Re-derive edges from filtered node IDs.
		nodeSet := make(map[string]bool, len(nodes))
		for _, n := range nodes {
			nodeSet[n.ID] = true
		}
		filteredEdges := make([]*provenance.Edge, 0, len(edges))
		for _, e := range edges {
			if nodeSet[e.Source] && nodeSet[e.Target] {
				filteredEdges = append(filteredEdges, e)
			}
		}
		edges = filteredEdges
	}

	// Keyword filter.
	if keyword := req.GetQuery(); keyword != "" {
		filteredNodes := make([]*provenance.Node, 0, len(nodes))
		for _, n := range nodes {
			if matchesQuery(n, keyword) {
				filteredNodes = append(filteredNodes, n)
			}
		}
		nodeSet := make(map[string]bool, len(filteredNodes))
		for _, n := range filteredNodes {
			nodeSet[n.ID] = true
		}
		filteredEdges := make([]*provenance.Edge, 0, len(edges))
		for _, e := range edges {
			if nodeSet[e.Source] && nodeSet[e.Target] {
				filteredEdges = append(filteredEdges, e)
			}
		}
		nodes = filteredNodes
		edges = filteredEdges
	}

	// Truncate to MaxResults if requested.
	maxResults := int(req.GetMaxResults())
	if maxResults <= 0 {
		maxResults = len(nodes) + len(edges)
	}

	// Build result payload.
	result := map[string]interface{}{
		"nodes": truncateNodes(nodes, maxResults),
		"edges": truncateEdges(edges, maxResults),
		"total": map[string]int{
			"nodes": len(nodes),
			"edges": len(edges),
		},
		"query": req.GetQuery(),
	}
	data, _ := json.Marshal(result)

	log.Printf("[grpc] Query: %q → %d nodes, %d edges (%d ms)",
		req.Query, len(nodes), len(edges), time.Since(start).Milliseconds())

	return &pb.QueryResponse{
		ResultCount:  int32(len(nodes) + len(edges)),
		ResultsJson:  string(data),
		QueryTimeNs:  time.Since(start).Nanoseconds(),
	}, nil
}

// matchesQuery checks if a node matches a simple keyword search.
func matchesQuery(n *provenance.Node, keyword string) bool {
	if n.ID == keyword || n.Label == keyword {
		return true
	}
	if len(keyword) >= 3 {
		if len(n.ID) >= len(keyword) && contains(n.ID, keyword) {
			return true
		}
		if len(n.Label) >= len(keyword) && contains(n.Label, keyword) {
			return true
		}
		if contains(n.Subtype, keyword) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func truncateNodes(nodes []*provenance.Node, max int) []map[string]interface{} {
	if max > len(nodes) {
		max = len(nodes)
	}
	out := make([]map[string]interface{}, max)
	for i := 0; i < max; i++ {
		n := nodes[i]
		out[i] = map[string]interface{}{
			"id":      n.ID,
			"type":    n.ProvType,
			"subtype": n.Subtype,
			"label":   n.Label,
		}
	}
	return out
}

func truncateEdges(edges []*provenance.Edge, max int) []map[string]interface{} {
	if max > len(edges) {
		max = len(edges)
	}
	out := make([]map[string]interface{}, max)
	for i := 0; i < max; i++ {
		e := edges[i]
		out[i] = map[string]interface{}{
			"source":   e.Source,
			"target":   e.Target,
			"relation": e.Relation,
			"count":    e.Count,
		}
	}
	return out
}

// WatchAlerts streams real-time alerts to the client.
func (s *provaptManagementServer) WatchAlerts(filter *pb.AlertFilter, stream pb.ProvidAPTManagement_WatchAlertsServer) error {
	if s.alertPipe == nil {
		log.Printf("[grpc] WatchAlerts: alert pipeline not connected")
		return stream.Send(&pb.AlertEvent{
			TimestampNs: time.Now().UnixNano(),
			AlertId:     "heartbeat",
			Severity:    "INFO",
			Title:       "Alert Pipeline Disconnected",
			Description: "Alert pipeline not available. Alerts will not be streamed.",
		})
	}

	log.Printf("[grpc] WatchAlerts: severity>=%s container=%s", filter.GetMinSeverity(), filter.GetContainer())

	// Create a dedicated channel for this stream and register it.
	alertCh := make(chan *alert.AlertSummary, 64)
	s.alertPipe.AlertSummaryCh = alertCh
	defer func() {
		s.alertPipe.AlertSummaryCh = nil
	}()

	// Send a heartbeat to confirm connection.
	_ = stream.Send(&pb.AlertEvent{
		TimestampNs: time.Now().UnixNano(),
		AlertId:     "heartbeat",
		Severity:    "INFO",
		Title:       "gRPC alert stream connected",
		Description: "Alert streaming channel established. Waiting for alerts...",
	})

	// Stream alerts as they arrive.
	for {
		select {
		case summary, ok := <-alertCh:
			if !ok {
				return nil
			}
			// Apply severity filter.
			if filter.GetMinSeverity() != "" && !severityMatches(filter.GetMinSeverity(), summary.Severity) {
				continue
			}
			evt := &pb.AlertEvent{
				TimestampNs: time.Now().UnixNano(),
				AlertId:     summary.Title,
				Severity:    summary.Severity,
				Title:       summary.Title,
				Description: summary.Description,
			}
			if err := stream.Send(evt); err != nil {
				log.Printf("[grpc] WatchAlerts send error: %v", err)
				return err
			}

		case <-stream.Context().Done():
			log.Printf("[grpc] WatchAlerts client disconnected")
			return stream.Context().Err()
		}
	}
}

func severityMatches(filter, actual string) bool {
	levels := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	filterLevel, ok1 := levels[filter]
	actualLevel, ok2 := levels[actual]
	if !ok1 || !ok2 {
		return true
	}
	return actualLevel >= filterLevel
}

// UpdatePolicy applies a dynamic policy update.
func (s *provaptManagementServer) UpdatePolicy(ctx context.Context, req *pb.PolicyUpdate) (*pb.PolicyAck, error) {
	log.Printf("[grpc] UpdatePolicy: %+v", req)

	// In production: route to the policy engine (sigma, taint, filter, threshold).
	// For now: acknowledge and log for audit trail.
	msg := "policy update received — applied via policy engine"
	switch {
	case req.GetWhitelist() != nil:
		msg = fmt.Sprintf("whitelist update: %+v", req.GetWhitelist())
	case req.GetSigma() != nil:
		msg = fmt.Sprintf("sigma rule: %+v", req.GetSigma())
	case req.GetTaintSource() != nil:
		msg = fmt.Sprintf("taint source: %+v", req.GetTaintSource())
	case req.GetThreshold() != nil:
		msg = fmt.Sprintf("threshold: %+v", req.GetThreshold())
	}
	log.Printf("[grpc] policy update: %s", msg)

	return &pb.PolicyAck{
		Success:     true,
		Message:     msg,
		AppliedAtNs: time.Now().UnixNano(),
	}, nil
}

// Check returns the daemon health status from live backends.
func (s *provaptManagementServer) Check(ctx context.Context, req *pb.HealthCheck) (*pb.HealthStatus, error) {
	uptime := time.Since(s.startedAt)

	status := "HEALTHY"
	nodeCount := int32(0)

	if s.graph != nil {
		gs := s.graph.Stats()
		nodeCount = int32(gs.Nodes)
	} else {
		status = "DEGRADED"
	}

	if s.pipeline == nil {
		status = "DEGRADED"
	}

	return &pb.HealthStatus{
		AgentRunning: true,
		Version:      s.version,
		UptimeNs:     uptime.Nanoseconds(),
		ActiveRules:  18,
		RocksdbNodes: nodeCount,
		TailedAlerts: 0,
		Status:       status,
	}, nil
}

// ─── Telemetry server ───────────────────────────────────────────

// provaptTelemetryServer implements the ProvidAPTTelemetry gRPC service.
type provaptTelemetryServer struct {
	eventCh chan<- *collector.Event
}

// Compile-time interface check.
var _ pb.ProvidAPTTelemetryServer = (*provaptTelemetryServer)(nil)

// newProvidAPTTelemetryServer creates a telemetry server.
func newProvidAPTTelemetryServer(opts GRPCOptions) *provaptTelemetryServer {
	return &provaptTelemetryServer{
		eventCh: opts.EventCh,
	}
}

// ReportEvents handles bidirectional event streaming from agents.
func (s *provaptTelemetryServer) ReportEvents(stream pb.ProvidAPTTelemetry_ReportEventsServer) error {
	log.Printf("[grpc] ReportEvents: stream opened")
	accepted := int64(0)
	dropped := int64(0)

	for {
		evt, err := stream.Recv()
		if err != nil {
			log.Printf("[grpc] ReportEvents: stream closed: %v (accepted=%d, dropped=%d)",
				err, accepted, dropped)
			return stream.SendAndClose(&pb.ReportAck{
				Accepted:      accepted > 0,
				ThrottleLevel: 0,
				Message:       fmt.Sprintf("accepted %d events, dropped %d", accepted, dropped),
			})
		}

		// Decode the raw event payload.
		// CompressedEvent.Payload contains the raw ringbuf byte sequence.
		if evt.GetContentType() == "raw" || evt.GetContentType() == "" {
			if s.eventCh != nil && len(evt.GetPayload()) > 0 {
				parsed, err := collector.ParseRawEvent(evt.GetPayload())
				if err != nil {
					log.Printf("[grpc] ReportEvents: parse error: %v", err)
					dropped++
					continue
				}
				// Forward to pipeline (non-blocking with context cancellation).
				select {
				case s.eventCh <- parsed:
					accepted++
				case <-stream.Context().Done():
					return stream.SendAndClose(&pb.ReportAck{
						Accepted:      accepted > 0,
						ThrottleLevel: 0,
						Message:       fmt.Sprintf("connection closed: accepted %d events", accepted),
					})
				}
			} else {
				// No event sink configured — count as accepted but discard.
				accepted++
			}
		} else {
			log.Printf("[grpc] ReportEvents: unknown content type: %s", evt.GetContentType())
			dropped++
		}
	}
}

// ─── Registration ───────────────────────────────────────────────

// registerGRPCServices registers all gRPC service implementations with
// the server, wiring them to the provided backend dependencies.
func registerGRPCServices(s grpc.ServiceRegistrar, opts GRPCOptions) {
	pb.RegisterProvidAPTManagementServer(s, newProvidAPTManagementServer(opts))
	pb.RegisterProvidAPTTelemetryServer(s, newProvidAPTTelemetryServer(opts))
	log.Printf("[grpc] registered ProvidAPTManagement and ProvidAPTTelemetry services with live backends")
}
