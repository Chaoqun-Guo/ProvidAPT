// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
)

// GRPCServer serves provenance data via gRPC for SIEM integration.
type GRPCServer struct {
	server *grpc.Server
	addr   string
}

// NewGRPCServer creates a gRPC server with registered management and telemetry services.
func NewGRPCServer(addr string) *GRPCServer {
	srv := grpc.NewServer()
	registerGRPCServices(srv)
	return &GRPCServer{
		server: srv,
		addr:   addr,
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
