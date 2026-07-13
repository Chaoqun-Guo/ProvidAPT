// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/pipeline"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/policy/alert"
	"google.golang.org/grpc"
)

// GRPCOptions wires backend dependencies into the gRPC server.
type GRPCOptions struct {
	// Graph is the in-memory provenance DAG for graph queries.
	Graph *provenance.Graph

	// Pipeline is the event ingestion pipeline for stats and event injection.
	Pipeline *pipeline.Pipeline

	// AlertPipeline, if set, enables WatchAlerts streaming.
	AlertPipeline *alert.AlertPipeline

	// EventCh, if set, receives decoded events from ReportEvents.
	EventCh chan<- *collector.Event

	// TelemetryStorePath, if set, receives ReportEvents metadata and payloads
	// as NDJSON for durable control-plane ingestion/audit.
	TelemetryStorePath string

	// Version is the agent version string.
	Version string
}

// GRPCServer serves provenance data via gRPC for SIEM integration.
type GRPCServer struct {
	server *grpc.Server
	addr   string
	opts   GRPCOptions
}

// NewGRPCServer creates a gRPC server with registered management and
// telemetry services wired to the provided backend dependencies.
func NewGRPCServer(addr string, opts GRPCOptions) *GRPCServer {
	srv := grpc.NewServer()
	registerGRPCServices(srv, opts)
	return &GRPCServer{
		server: srv,
		addr:   addr,
		opts:   opts,
	}
}

// Start begins listening on the configured address.
func (s *GRPCServer) Start() error {
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	return s.server.Serve(lis)
}

// Stop gracefully shuts down the server.
func (s *GRPCServer) Stop() {
	s.server.GracefulStop()
}
