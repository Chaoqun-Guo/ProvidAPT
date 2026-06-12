// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"
	"google.golang.org/grpc"
)

// provaptManagementServer implements the ProvidAPTManagement gRPC service.
type provaptManagementServer struct {
	startedAt time.Time
	ruleCount int
}

// Compile-time interface check.
var _ pb.ProvidAPTManagementServer = (*provaptManagementServer)(nil)

// newProvidAPTManagementServer creates a management server with live status.
func newProvidAPTManagementServer() *provaptManagementServer {
	return &provaptManagementServer{
		startedAt: time.Now(),
		ruleCount: 18, // built-in rules
	}
}

// Query handles ProvQL graph queries.
func (s *provaptManagementServer) Query(ctx context.Context, req *pb.QueryRequest) (*pb.QueryResponse, error) {
	log.Printf("[grpc] Query: %q (max=%d)", req.Query, req.MaxResults)
	// In production: execute ProvQL against the graph store.
	// For now: return a stub indicating the query was accepted.
	result := map[string]interface{}{
		"query":    req.Query,
		"status":   "accepted",
		"note":     "graph query engine not yet connected",
	}
	data, _ := json.Marshal(result)
	return &pb.QueryResponse{
		ResultCount:  0,
		ResultsJson:  string(data),
		QueryTimeNs:  0,
	}, nil
}

// WatchAlerts streams real-time alerts to the client.
func (s *provaptManagementServer) WatchAlerts(filter *pb.AlertFilter, stream pb.ProvidAPTManagement_WatchAlertsServer) error {
	log.Printf("[grpc] WatchAlerts: severity>=%s container=%s", filter.MinSeverity, filter.Container)
	// In production: subscribe to the alert pipeline and stream matching alerts.
	// For now: send a heartbeat and close.
	_ = stream.Send(&pb.AlertEvent{
		TimestampNs: time.Now().UnixNano(),
		AlertId:     "heartbeat",
		Severity:    "INFO",
		Title:       "gRPC alert stream connected",
		Description: "Alert streaming channel established. Waiting for alerts...",
	})
	return nil
}

// UpdatePolicy applies a dynamic policy update (whitelist, sigma rule, taint source, threshold).
func (s *provaptManagementServer) UpdatePolicy(ctx context.Context, req *pb.PolicyUpdate) (*pb.PolicyAck, error) {
	log.Printf("[grpc] UpdatePolicy: %+v", req)
	return &pb.PolicyAck{
		Success:    true,
		Message:    "policy update accepted (stub — actual application not yet implemented)",
		AppliedAtNs: time.Now().UnixNano(),
	}, nil
}

// Check returns the daemon health status.
func (s *provaptManagementServer) Check(ctx context.Context, req *pb.HealthCheck) (*pb.HealthStatus, error) {
	uptime := time.Since(s.startedAt)
	return &pb.HealthStatus{
		AgentRunning: true,
		Version:      version.Version,
		UptimeNs:     uptime.Nanoseconds(),
		ActiveRules:  int32(s.ruleCount),
		RocksdbNodes: 0,
		TailedAlerts: 0,
		Status:       "HEALTHY",
	}, nil
}

// provaptTelemetryServer implements the ProvidAPTTelemetry gRPC service.
type provaptTelemetryServer struct{}

// Compile-time interface check.
var _ pb.ProvidAPTTelemetryServer = (*provaptTelemetryServer)(nil)

// ReportEvents handles bidirectional event streaming from agents.
func (s *provaptTelemetryServer) ReportEvents(stream pb.ProvidAPTTelemetry_ReportEventsServer) error {
	log.Printf("[grpc] ReportEvents: stream opened")
	// In production: decode CompressedEvent payloads and route to the pipeline.
	// For now: accept the stream and acknowledge.
	return stream.SendAndClose(&pb.ReportAck{
		Accepted:      true,
		ThrottleLevel: 0,
		Message:       fmt.Sprintf("stream accepted at %s", time.Now().Format(time.RFC3339)),
	})
}

// registerGRPCServices registers all gRPC service implementations with the server.
func registerGRPCServices(s grpc.ServiceRegistrar) {
	pb.RegisterProvidAPTManagementServer(s, newProvidAPTManagementServer())
	pb.RegisterProvidAPTTelemetryServer(s, &provaptTelemetryServer{})
	log.Printf("[grpc] registered ProvidAPTManagement and ProvidAPTTelemetry services")
}
