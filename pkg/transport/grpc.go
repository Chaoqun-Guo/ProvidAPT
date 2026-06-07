// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	mgmtpb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/metrics"
)

// GrpcClient manages a gRPC connection to the central analysis server.
// It provides a `Send` method for transmitting compressed provenance data
// and handles reconnection with keepalive to detect silent disconnects.
type GrpcClient struct {
	addr   string
	conn   *grpc.ClientConn
	client mgmtpb.ProvidAPTTelemetryClient
	opts   []grpc.DialOption
	mu     sync.Mutex
	closed bool

	// reconnect interval on failure
	retryDelay time.Duration
}

// NewGrpcClient creates a gRPC client for the given server address.
//
// In production, use `grpc.WithTransportCredentials(credentials.NewTLS(...))`
// for mTLS. See v2.1/mgmt/server.go for the mTLS server side.
func NewGrpcClient(addr string) *GrpcClient {
	return NewGrpcClientWithOpts(addr, []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	})
}

// NewGrpcClientWithOpts creates a gRPC client with custom dial options.
// Useful for production deployments requiring mTLS.
func NewGrpcClientWithOpts(addr string, opts []grpc.DialOption) *GrpcClient {
	defaults := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(64 * 1024 * 1024),
			grpc.MaxCallSendMsgSize(64 * 1024 * 1024),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             3 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	return &GrpcClient{
		addr:       addr,
		opts:       append(defaults, opts...),
		retryDelay: 5 * time.Second,
	}
}

// GrpcClientConfig holds mTLS configuration for the gRPC client.
type GrpcClientConfig struct {
	ServerAddr string
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
	EnableTLS  bool
}

// NewGrpcClientWithTLS creates a gRPC client with mTLS transport credentials.
//
//	client := transport.NewGrpcClientWithTLS(&transport.GrpcClientConfig{
//	    ServerAddr: "collector.providapt.io:50051",
//	    CertFile:   "/etc/providapt/certs/client.crt",
//	    KeyFile:    "/etc/providapt/certs/client.key",
//	    CAFile:     "/etc/providapt/certs/ca.crt",
//	    EnableTLS:  true,
//	})
func NewGrpcClientWithTLS(cfg *GrpcClientConfig) *GrpcClient {
	var creds credentials.TransportCredentials
	if cfg.EnableTLS {
		tlsCfg := loadTLSClientConfig(cfg)
		creds = credentials.NewTLS(tlsCfg)
	} else {
		creds = insecure.NewCredentials()
	}
	return NewGrpcClientWithOpts(cfg.ServerAddr, []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	})
}

// loadTLSClientConfig builds a tls.Config for mTLS client connections.
func loadTLSClientConfig(cfg *GrpcClientConfig) *tls.Config {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.ServerName != "" {
		tlsCfg.ServerName = cfg.ServerName
	}

	// Load client certificate
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err == nil {
			tlsCfg.Certificates = []tls.Certificate{cert}
		} else {
			log.Printf("[grpc] failed to load client cert: %v", err)
		}
	}

	// Load CA pool for server verification
	if cfg.CAFile != "" {
		caData, err := os.ReadFile(cfg.CAFile)
		if err == nil {
			caPool := x509.NewCertPool()
			if caPool.AppendCertsFromPEM(caData) {
				tlsCfg.RootCAs = caPool
			}
		} else {
			log.Printf("[grpc] failed to load CA file: %v", err)
		}
	}

	return tlsCfg
}

// Connect establishes the gRPC connection.
func (c *GrpcClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil
	}

	conn, err := grpc.Dial(c.addr, c.opts...)
	if err != nil {
		return err
	}

	c.conn = conn
	c.client = mgmtpb.NewProvidAPTTelemetryClient(conn)
	log.Printf("[grpc] connected to %s", c.addr)
	return nil
}

// Send transmits compressed provenance data over gRPC.
// The `data` parameter is expected to be Zstd-compressed protobuf bytes
// produced by Compressor.CompressProtobuf.
func (c *GrpcClient) Send(data []byte) error {
	// Ensure connected
	if err := c.Connect(); err != nil {
		return err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	client := c.client
	c.mu.Unlock()

	// Open a client stream for ReportEvents
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	stream, err := client.ReportEvents(ctx)
	if err != nil {
		log.Printf("[grpc] ReportEvents stream open failed: %v (will retry)", err)
		metrics.GrpcSendErrors.Inc()
		// Reset connection on failure so next Send retries
		c.mu.Lock()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
			c.client = nil
		}
		c.mu.Unlock()
		return err
	}

	// Send compressed event
	evt := &mgmtpb.CompressedEvent{
		Payload:      data,
		ContentType:  "full",
		OriginalSize: int64(len(data)),
		TimestampNs:  time.Now().UnixNano(),
	}
	if err := stream.Send(evt); err != nil {
		log.Printf("[grpc] send failed: %v", err)
		metrics.GrpcSendErrors.Inc()
		return err
	}

	// Close and get ack
	ack, err := stream.CloseAndRecv()
	if err != nil {
		log.Printf("[grpc] close/recv failed: %v", err)
		metrics.GrpcSendErrors.Inc()
		return err
	}

	metrics.GrpcSentBytes.Add(float64(len(data)))
	metrics.GrpcSendDuration.Observe(time.Since(start).Seconds())

	log.Printf("[grpc] sent %d bytes to %s (accepted=%v, throttle=%d)",
		len(data), c.addr, ack.Accepted, ack.ThrottleLevel)
	return nil
}

// SendWithContentType sends data with an explicit content type label.
func (c *GrpcClient) SendWithContentType(data []byte, contentType string) error {
	if err := c.Connect(); err != nil {
		return err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	client := c.client
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	stream, err := client.ReportEvents(ctx)
	if err != nil {
		metrics.GrpcSendErrors.Inc()
		return err
	}

	evt := &mgmtpb.CompressedEvent{
		Payload:      data,
		ContentType:  contentType,
		OriginalSize: int64(len(data)),
		TimestampNs:  time.Now().UnixNano(),
	}
	if err := stream.Send(evt); err != nil {
		metrics.GrpcSendErrors.Inc()
		return err
	}

	ack, err := stream.CloseAndRecv()
	if err != nil {
		metrics.GrpcSendErrors.Inc()
		return err
	}

	metrics.GrpcSentBytes.Add(float64(len(data)))
	metrics.GrpcSendDuration.Observe(time.Since(start).Seconds())

	log.Printf("[grpc] sent %d bytes (%s) to %s (throttle=%d)",
		len(data), contentType, c.addr, ack.ThrottleLevel)
	return nil
}

// Close shuts down the gRPC connection.
func (c *GrpcClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	c.closed = true

	if c.conn != nil {
		c.conn.Close()
		log.Printf("[grpc] connection to %s closed", c.addr)
	}
}
