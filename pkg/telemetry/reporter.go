package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/transport"
)

type Sender interface {
	SendWithContentType(data []byte, contentType string) error
	Close()
}

type ReporterConfig struct {
	Endpoint   string
	Interval   time.Duration
	EnableTLS  bool
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
}

type Summary struct {
	AgentID          string `json:"agent_id"`
	Version          string `json:"version"`
	Status           string `json:"status"`
	UptimeSeconds    int64  `json:"uptime_seconds"`
	EventsIngested   uint64 `json:"events_ingested"`
	EventsDropped    uint64 `json:"events_dropped"`
	MemoryBytes      uint64 `json:"memory_bytes"`
	PipelineHealthy  bool   `json:"pipeline_healthy"`
	StoreHealthy     bool   `json:"store_healthy"`
	AttachmentMode   string `json:"attachment_mode,omitempty"`
	TimestampUnixSec int64  `json:"timestamp_unix_sec"`
}

type ReporterStatus struct {
	Enabled             bool      `json:"enabled"`
	LastAttempt         time.Time `json:"last_attempt,omitempty"`
	LastSuccess         time.Time `json:"last_success,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastError           string    `json:"last_error,omitempty"`
}

type Reporter struct {
	cfg      ReporterConfig
	sender   Sender
	build    func() Summary
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.RWMutex
	status   ReporterStatus
	interval time.Duration
}

func NewReporter(cfg ReporterConfig, build func() Summary) *Reporter {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Reporter{
		cfg:      cfg,
		build:    build,
		interval: interval,
		status: ReporterStatus{
			Enabled: cfg.Endpoint != "",
		},
	}
}

func (r *Reporter) Start(ctx context.Context) error {
	if r.cfg.Endpoint == "" {
		return nil
	}
	if r.sender == nil {
		if r.cfg.EnableTLS {
			r.sender = transport.NewGrpcClientWithTLS(&transport.GrpcClientConfig{
				ServerAddr: r.cfg.Endpoint,
				CertFile:   r.cfg.CertFile,
				KeyFile:    r.cfg.KeyFile,
				CAFile:     r.cfg.CAFile,
				ServerName: r.cfg.ServerName,
				EnableTLS:  true,
			})
		} else {
			r.sender = transport.NewGrpcClient(r.cfg.Endpoint)
		}
	}
	loopCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.wg.Add(1)
	go r.loop(loopCtx)
	return nil
}

func (r *Reporter) loop(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	_ = r.ReportNow()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = r.ReportNow()
		}
	}
}

func (r *Reporter) ReportNow() error {
	if r.sender == nil || r.build == nil {
		return nil
	}
	r.mu.Lock()
	r.status.LastAttempt = time.Now()
	r.mu.Unlock()

	summary := r.build()
	if summary.TimestampUnixSec == 0 {
		summary.TimestampUnixSec = time.Now().Unix()
	}
	payload, err := json.Marshal(summary)
	if err != nil {
		r.recordFailure(fmt.Errorf("marshal summary: %w", err))
		return err
	}
	if err := r.sender.SendWithContentType(payload, "summary"); err != nil {
		r.recordFailure(err)
		return err
	}
	r.recordSuccess()
	return nil
}

func (r *Reporter) Status() ReporterStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

func (r *Reporter) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	if r.sender != nil {
		r.sender.Close()
	}
}

func (r *Reporter) recordFailure(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.ConsecutiveFailures++
	r.status.LastError = err.Error()
}

func (r *Reporter) recordSuccess() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.LastSuccess = time.Now()
	r.status.ConsecutiveFailures = 0
	r.status.LastError = ""
}

func (r *Reporter) SetSender(sender Sender) {
	r.sender = sender
}
