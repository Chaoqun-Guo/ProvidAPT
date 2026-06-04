// Package mgmt implements the ProvidAPT v2.1 remote management
// architecture with gRPC, dynamic policy delivery, and mTLS.
package mgmt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	mgmtpb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/certauth"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/analyzer"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/control"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/policy/sigma"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
)

// ═══════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════

// Server implements the ProvidAPTManagement gRPC service.
type Server struct {
	mu       sync.Mutex
	addr     string
	server   *grpc.Server
	config   *ServerConfig
	ctrl     *control.Controller
	analyzer *analyzer.Analyzer
	alertSub alertSubscription
	started  time.Time
}

// alertSubscription manages a dynamic list of WatchAlerts subscribers.
type alertSubscription struct {
	mu      sync.Mutex
	subs    []chan *mgmtpb.AlertEvent
	maxSubs int
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

// SetController attaches the eBPF controller for runtime policy operations.
func (s *Server) SetController(ctrl *control.Controller) {
	s.ctrl = ctrl
}

// SetAnalyzer attaches the analyzer for alert streaming and config reload.
func (s *Server) SetAnalyzer(anz *analyzer.Analyzer) {
	s.analyzer = anz
}

// StartAlertForwarder begins forwarding analyzer alerts to all gRPC subscribers.
// Runs until alertCh is closed.
func (s *Server) StartAlertForwarder(alertCh <-chan *analyzer.Alert) {
	go func() {
		for al := range alertCh {
			evt := alertToEvent(al)
			s.alertSub.broadcast(evt)
		}
	}()
}

func alertToEvent(al *analyzer.Alert) *mgmtpb.AlertEvent {
	return &mgmtpb.AlertEvent{
		TimestampNs: al.DetectedAt.UnixNano(),
		AlertId:     string(al.Pattern) + ":" + al.AlertNodeID,
		Severity:    severityString(al.Severity),
		Title:       al.Headline,
		Description: al.Reason,
	}
}

func severityString(sev analyzer.Severity) string {
	switch sev {
	case analyzer.SeverityInfo:
		return "INFO"
	case analyzer.SeverityLow:
		return "LOW"
	case analyzer.SeverityMedium:
		return "MEDIUM"
	case analyzer.SeverityHigh:
		return "HIGH"
	case analyzer.SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (as *alertSubscription) broadcast(evt *mgmtpb.AlertEvent) {
	as.mu.Lock()
	defer as.mu.Unlock()
	for _, ch := range as.subs {
		select {
		case ch <- evt:
		default:
		}
	}
}

func (as *alertSubscription) subscribe(ch chan *mgmtpb.AlertEvent) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.maxSubs == 0 {
		as.maxSubs = 64
	}
	if len(as.subs) >= as.maxSubs {
		return
	}
	as.subs = append(as.subs, ch)
}

func (as *alertSubscription) unsubscribe(ch chan *mgmtpb.AlertEvent) {
	as.mu.Lock()
	defer as.mu.Unlock()
	for i, s := range as.subs {
		if s == ch {
			as.subs = append(as.subs[:i], as.subs[i+1:]...)
			close(ch)
			return
		}
	}
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

	resp := &mgmtpb.QueryResponse{
		ResultsJson: `{"message":"query received"}`,
		QueryTimeNs: time.Now().UnixNano(),
	}

	// If we have an analyzer, include alert count
	if s.analyzer != nil {
		alerts := s.analyzer.Alerts()
		resp.ResultsJson = fmt.Sprintf(`{"alert_count":%d}`, len(alerts))
	}

	return resp, nil
}

// WatchAlerts streams real-time alerts to authorized clients.
func (s *Server) WatchAlerts(filter *mgmtpb.AlertFilter, stream mgmtpb.ProvidAPTManagement_WatchAlertsServer) error {
	clientInfo := clientIdentity(stream.Context())
	log.Printf("[mgmt] Alert stream started from %s (min_severity=%s)",
		clientInfo, filter.MinSeverity)

	ch := make(chan *mgmtpb.AlertEvent, 64)
	s.alertSub.subscribe(ch)
	defer s.alertSub.unsubscribe(ch)

	for {
		select {
		case evt := <-ch:
			if err := stream.Send(evt); err != nil {
				return fmt.Errorf("send alert: %w", err)
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

// UpdatePolicy handles real-time policy updates.
func (s *Server) UpdatePolicy(ctx context.Context, update *mgmtpb.PolicyUpdate) (*mgmtpb.PolicyAck, error) {
	clientInfo := clientIdentity(ctx)

	ack := &mgmtpb.PolicyAck{
		Success:     true,
		AppliedAtNs: time.Now().UnixNano(),
	}

	switch u := update.Update.(type) {
	case *mgmtpb.PolicyUpdate_Whitelist:
		ack.Message = s.applyWhitelistUpdate(u.Whitelist, clientInfo)
	case *mgmtpb.PolicyUpdate_Sigma:
		log.Printf("[mgmt] Policy update from %s: sigma rule %s %s",
			clientInfo, u.Sigma.Action, u.Sigma.RuleId)

		if s.analyzer == nil {
			ack.Message = "analyzer not available"
			break
		}

		switch u.Sigma.Action {
		case "add", "update":
			parsed, err := sigma.ParseRule([]byte(u.Sigma.RuleYaml))
			if err != nil {
				ack.Success = false
				ack.Message = fmt.Sprintf("parse error: %v", err)
				break
			}
			s.analyzer.AddSigmaRule(u.Sigma.RuleId, parsed)
			ack.Message = fmt.Sprintf("sigma rule %s applied", u.Sigma.RuleId)
		case "remove":
			s.analyzer.RemoveSigmaRule(u.Sigma.RuleId)
			ack.Message = fmt.Sprintf("sigma rule %s removed", u.Sigma.RuleId)
		default:
			ack.Success = false
			ack.Message = fmt.Sprintf("unknown action %q", u.Sigma.Action)
		}
	case *mgmtpb.PolicyUpdate_TaintSource:
		log.Printf("[mgmt] Policy update from %s: taint source %s %s (label=%s)",
			clientInfo, u.TaintSource.Action, u.TaintSource.IpPrefix, u.TaintSource.Label)
		switch u.TaintSource.Action {
		case "add":
			if u.TaintSource.Label != "" {
				analyzer.AddUntrustedComm(u.TaintSource.Label)
				ack.Message = fmt.Sprintf("taint source %s added (label=%s)", u.TaintSource.IpPrefix, u.TaintSource.Label)
			} else {
				ack.Message = fmt.Sprintf("taint source %s added (no label)", u.TaintSource.IpPrefix)
			}
		case "remove":
			if u.TaintSource.Label != "" {
				analyzer.RemoveUntrustedComm(u.TaintSource.Label)
				ack.Message = fmt.Sprintf("taint source %s removed (label=%s)", u.TaintSource.IpPrefix, u.TaintSource.Label)
			} else {
				ack.Message = fmt.Sprintf("taint source %s removed", u.TaintSource.IpPrefix)
			}
		default:
			ack.Success = false
			ack.Message = fmt.Sprintf("unknown taint action %q", u.TaintSource.Action)
		}
	default:
		ack.Success = false
		ack.Message = "unknown update type"
	}

	return ack, nil
}

func (s *Server) applyWhitelistUpdate(w *mgmtpb.WhitelistUpdate, clientInfo string) string {
	if s.ctrl == nil {
		log.Printf("[mgmt] whitelist update from %s: controller not available", clientInfo)
		return "controller not available"
	}

	log.Printf("[mgmt] Policy update from %s: whitelist %s %s=%s",
		clientInfo, w.Action, w.Target, w.Value)

	switch w.Target {
	case "pid":
		pid, err := strconv.ParseUint(w.Value, 10, 32)
		if err != nil {
			return fmt.Sprintf("invalid pid %q", w.Value)
		}
		switch w.Action {
		case "add":
			if err := s.ctrl.ExcludePID(uint32(pid)); err != nil {
				return fmt.Sprintf("exclude pid failed: %v", err)
			}
			return fmt.Sprintf("PID %d excluded", pid)
		case "remove":
			if err := s.ctrl.UnExcludePID(uint32(pid)); err != nil {
				return fmt.Sprintf("unexclude pid failed: %v", err)
			}
			return fmt.Sprintf("PID %d unexcluded", pid)
		}

	case "comm":
		// Comm-based whitelist — currently unsupported via gRPC
		return "comm-based whitelist requires /proc scan, use pid instead"

	case "path":
		switch w.Action {
		case "add":
			if err := s.ctrl.AddHotPath(w.Value); err != nil {
				return fmt.Sprintf("add hot path failed: %v", err)
			}
			return fmt.Sprintf("hot path %s added", w.Value)
		case "remove":
			if err := s.ctrl.RemoveHotPath(w.Value); err != nil {
				return fmt.Sprintf("remove hot path failed: %v", err)
			}
			return fmt.Sprintf("hot path %s removed", w.Value)
		case "clear":
			if err := s.ctrl.ClearHotPaths(); err != nil {
				return fmt.Sprintf("clear hot paths failed: %v", err)
			}
			return "all hot paths cleared"
		}
	}

	return fmt.Sprintf("unknown whitelist target %q or action %q", w.Target, w.Action)
}

// Check handles health check requests.
func (s *Server) Check(ctx context.Context, req *mgmtpb.HealthCheck) (*mgmtpb.HealthStatus, error) {
	hs := &mgmtpb.HealthStatus{
		AgentRunning: true,
		Version:     version.String(),
		UptimeNs:    time.Since(s.started).Nanoseconds(),
		Status:      "HEALTHY",
	}

	if s.analyzer != nil {
		hs.TailedAlerts = int32(len(s.analyzer.Alerts()))
	}

	return hs, nil
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
	// Try persistent certauth (production use)
	certDir := filepath.Join(os.TempDir(), "providapt-certs")
	os.MkdirAll(certDir, 0700)

	caDir := filepath.Join(certDir, "ca")
	srvDir := filepath.Join(certDir, "server")
	cliDir := filepath.Join(certDir, "client")

	cfg := &certauth.Config{
		CADir:      caDir,
		ServerDir:  srvDir,
		ClientDir:  cliDir,
		ValidYears: 10,
		KeyBits:    4096,
	}

	certFile, keyFile, _, err := certauth.Initialize(cfg)
	if err == nil {
		log.Printf("[mgmt] using certauth-generated certificates in %s", certDir)
		return tls.LoadX509KeyPair(certFile, keyFile)
	}

	// Fallback: ephemeral self-signed cert (dev only)
	log.Printf("[mgmt] certauth init failed (%v); generating ephemeral self-signed cert", err)
	return generateEphemeralCert()
}

// generateEphemeralCert creates an in-memory self-signed certificate for development use.
func generateEphemeralCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ProvidAPT"},
			CommonName:   "providapt-dev",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
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
