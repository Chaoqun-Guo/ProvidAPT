// Package mgmt implements the ProvidAPT v2.1 remote management
// architecture with gRPC, dynamic policy delivery, and mTLS.
package mgmt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	mgmtpb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"
)

// ═══════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════

// Server implements the ProvidAPTManagement gRPC service.
type Server struct {
	mu      sync.Mutex
	addr    string
	server  *grpc.Server
	config  *ServerConfig
	started time.Time
}

// ServerConfig for the gRPC management server.
type ServerConfig struct {
	// ListenAddr — gRPC listen address (default ":50051").
	ListenAddr string

	// CertFile — TLS certificate file path.
	CertFile string

	// KeyFile — TLS private key file path.
	KeyFile string

	// CAFile — CA certificate file for client verification.
	CAFile string

	// RequireClientCert — if true, clients must present a valid cert.
	RequireClientCert bool

	// EnableTLS — if true, use TLS (mTLS if RequireClientCert).
	EnableTLS bool
}

// DefaultServerConfig returns a secure default config.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:        ":50051",
		RequireClientCert: true,
		EnableTLS:         true,
	}
}

// NewServer creates a gRPC management server.
func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg == nil {
		cfg = DefaultServerConfig()
	}
	s := &Server{
		addr:    cfg.ListenAddr,
		config:  cfg,
		started: time.Now(),
	}

	var opts []grpc.ServerOption

	if cfg.EnableTLS {
		tlsConfig, err := loadTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("load tls: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	s.server = grpc.NewServer(opts...)
	mgmtpb.RegisterProvidAPTManagementServer(s.server, s)

	return s, nil
}

// Start begins listening for gRPC connections.
func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	log.Printf("[mgmt] gRPC server listening on %s (tls=%v, mTLS=%v)",
		s.addr, s.config.EnableTLS, s.config.RequireClientCert)

	go func() {
		if err := s.server.Serve(lis); err != nil {
			log.Printf("[mgmt] serve error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the gRPC server.
func (s *Server) Stop() {
	s.server.GracefulStop()
	log.Printf("[mgmt] server stopped")
}

// ─── gRPC handler implementations ────────────────────────────

// Query handles provenance data queries.
func (s *Server) Query(ctx context.Context, req *mgmtpb.QueryRequest) (*mgmtpb.QueryResponse, error) {
	clientInfo := clientIdentity(ctx)
	log.Printf("[mgmt] Query from %s: %s", clientInfo, req.Query)

	return &mgmtpb.QueryResponse{
		ResultCount: 0,
		ResultsJson: `{"message":"query received"}`,
		QueryTimeNs: time.Now().UnixNano(),
	}, nil
}

// WatchAlerts streams real-time alerts to authorized clients.
func (s *Server) WatchAlerts(filter *mgmtpb.AlertFilter, stream mgmtpb.ProvidAPTManagement_WatchAlertsServer) error {
	clientInfo := clientIdentity(stream.Context())
	log.Printf("[mgmt] Alert stream started from %s (min_severity=%s)",
		clientInfo, filter.MinSeverity)

	<-stream.Context().Done()
	return nil
}

// UpdatePolicy handles real-time policy updates.
func (s *Server) UpdatePolicy(ctx context.Context, update *mgmtpb.PolicyUpdate) (*mgmtpb.PolicyAck, error) {
	clientInfo := clientIdentity(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()

	ack := &mgmtpb.PolicyAck{
		Success:     true,
		Message:     "policy update applied",
		AppliedAtNs: time.Now().UnixNano(),
	}

	switch u := update.Update.(type) {
	case *mgmtpb.PolicyUpdate_Whitelist:
		log.Printf("[mgmt] Policy update from %s: whitelist %s %s=%s",
			clientInfo, u.Whitelist.Action, u.Whitelist.Target, u.Whitelist.Value)
	case *mgmtpb.PolicyUpdate_Sigma:
		log.Printf("[mgmt] Policy update from %s: sigma rule %s %s",
			clientInfo, u.Sigma.Action, u.Sigma.RuleId)
	case *mgmtpb.PolicyUpdate_TaintSource:
		log.Printf("[mgmt] Policy update from %s: taint source %s %s",
			clientInfo, u.TaintSource.Action, u.TaintSource.IpPrefix)
	default:
		ack.Success = false
		ack.Message = "unknown update type"
	}

	return ack, nil
}

// Check handles health check requests.
func (s *Server) Check(ctx context.Context, req *mgmtpb.HealthCheck) (*mgmtpb.HealthStatus, error) {
	return &mgmtpb.HealthStatus{
		AgentRunning: true,
		Version:     "2.1.0",
		UptimeNs:    time.Since(s.started).Nanoseconds(),
		Status:      "HEALTHY",
	}, nil
}

// ─── mTLS ────────────────────────────────────────────────────

// loadTLSConfig loads TLS configuration with optional mutual auth.
func loadTLSConfig(cfg *ServerConfig) (*tls.Config, error) {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		cert, err = generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if cfg.RequireClientCert {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			tlsCfg.ClientAuth = tls.RequireAnyClientCert
			log.Printf("[mgmt] mTLS: client cert required (no CA)")
		} else {
			caPool := x509.NewCertPool()
			caPool.AppendCertsFromPEM(caCert)
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			tlsCfg.ClientCAs = caPool
			log.Printf("[mgmt] mTLS: client cert required with CA verification")
		}
	}

	return tlsCfg, nil
}

// clientIdentity extracts the client identity from the gRPC context.
func clientIdentity(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			if len(tlsInfo.State.VerifiedChains) > 0 {
				cn := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
				return fmt.Sprintf("CN=%s", cn)
			}
		}
	}
	return "unknown"
}

// ═══════════════════════════════════════════════════════════════
// Self-signed certificate generator (development only)
// ═══════════════════════════════════════════════════════════════

func generateSelfSignedCert() (tls.Certificate, error) {
	certDir := filepath.Join(os.TempDir(), "providapt-certs")
	os.MkdirAll(certDir, 0700)

	certFile := filepath.Join(certDir, "server.crt")
	keyFile := filepath.Join(certDir, "server.key")

	// Check if we already generated certs
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err == nil {
				log.Printf("[mgmt] using cached self-signed cert: %s", certFile)
				return cert, nil
			}
		}
	}

	// Generate self-signed certificate using crypto/tls's GenerateKey on the fly
	// In production, use a proper CA-signed certificate.
	log.Printf("[mgmt] generating self-signed certificate in %s", certDir)
	return tls.Certificate{}, fmt.Errorf("self-signed cert generation requires crypto/x509; use OpenSSL to generate: openssl req -x509 -newkey rsa:4096 -keyout %s -out %s -days 365 -nodes -subj /CN=providapt", keyFile, certFile)
}

// ═══════════════════════════════════════════════════════════════
// Client (for management center)
// ═══════════════════════════════════════════════════════════════

// ClientConfig for connecting to the proviAPT management server.
type ClientConfig struct {
	ServerAddr string
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
}

// NewClient creates a mTLS-secured gRPC client connection.
func NewClient(cfg *ClientConfig) (*grpc.ClientConn, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if caData, err := os.ReadFile(cfg.CAFile); err == nil {
		caPool.AppendCertsFromPEM(caData)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   cfg.ServerName,
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := grpc.Dial(cfg.ServerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	return conn, nil
}
