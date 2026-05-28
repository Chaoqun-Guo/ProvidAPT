package api

import (
	"fmt"
	"net"

	"google.golang.org/grpc"
)

// GRPCServer serves provenance data via gRPC for SIEM integration.
type GRPCServer struct {
	server *grpc.Server
	addr   string
}

// NewGRPCServer creates a gRPC server (not yet registered with services).
func NewGRPCServer(addr string) *GRPCServer {
	return &GRPCServer{
		server: grpc.NewServer(),
		addr:   addr,
	}
}

// Start begins listening on the configured address.
func (s *GRPCServer) Start() error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	return s.server.Serve(lis)
}

// Stop gracefully shuts down the server.
func (s *GRPCServer) Stop() {
	s.server.GracefulStop()
}
