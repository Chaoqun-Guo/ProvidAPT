// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package export implements data export for ProvidAPT v2 including
// gRPC streaming, CEF/ASIM format integration, and JSON CLI output.
package grpcexport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// gRPC exporter
// ═══════════════════════════════════════════════════════════════

// ExportEvent is the wire format for gRPC streaming export.
type ExportEvent struct {
	AgentID     string `json:"agent_id"`
	Timestamp   int64  `json:"timestamp_ns"`
	EventType   uint32 `json:"event_type"`
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid"`
	UID         uint32 `json:"uid"`
	Comm        string `json:"comm"`
	Pathname    string `json:"pathname,omitempty"`
	Inode       uint64 `json:"inode,omitempty"`
	Daddr       uint32 `json:"daddr,omitempty"`
	Dport       uint32 `json:"dport,omitempty"`
	Score       float64 `json:"score,omitempty"`
	IsHighRisk  bool    `json:"is_high_risk"`
	SubgraphID  string  `json:"subgraph_id,omitempty"`
}

// GRPCExporterConfig configures the gRPC export client.
type GRPCExporterConfig struct {
	// RemoteAddr is the target gRPC server address.
	RemoteAddr string

	// AgentID uniquely identifies this agent.
	AgentID string

	// BatchSize accumulates events before sending (default 50).
	BatchSize int

	// FlushInterval flushes pending events periodically (default 5s).
	FlushInterval time.Duration

	// HighRiskOnly if true, only exports events with IsHighRisk=true.
	HighRiskOnly bool

	// ScoreThreshold exports only events with score >= this value.
	ScoreThreshold float64
}

// DefaultGRPCConfig returns sensible defaults.
func DefaultGRPCConfig() *GRPCExporterConfig {
	return &GRPCExporterConfig{
		RemoteAddr:    "localhost:50051",
		BatchSize:     50,
		FlushInterval: 5 * time.Second,
		HighRiskOnly:  false,
		ScoreThreshold: 0,
	}
}

// GRPCExporter manages streaming export to a remote server.
type GRPCExporter struct {
	cfg      *GRPCExporterConfig
	mu       sync.Mutex
	buffer   []*ExportEvent
	stopCh   chan struct{}
	wg       sync.WaitGroup
	totalSent int64
}

// NewGRPCExporter creates a gRPC export client.
func NewGRPCExporter(cfg *GRPCExporterConfig) *GRPCExporter {
	if cfg == nil {
		cfg = DefaultGRPCConfig()
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	return &GRPCExporter{
		cfg:    cfg,
		buffer: make([]*ExportEvent, 0, cfg.BatchSize),
		stopCh: make(chan struct{}),
	}
}

// Start begins the background flush goroutine.
func (e *GRPCExporter) Start() {
	e.wg.Add(1)
	go e.flushLoop()
	log.Printf("[export] gRPC exporter started → %s (batch=%d, interval=%v)",
		e.cfg.RemoteAddr, e.cfg.BatchSize, e.cfg.FlushInterval)
}

// Export queues an event for gRPC export.  Thread-safe.
// Returns true if the event was queued, false if filtered.
func (e *GRPCExporter) Export(evt *ExportEvent) bool {
	// Apply filters
	if e.cfg.HighRiskOnly && !evt.IsHighRisk {
		return false
	}
	if e.cfg.ScoreThreshold > 0 && evt.Score < e.cfg.ScoreThreshold {
		return false
	}

	e.mu.Lock()
	e.buffer = append(e.buffer, evt)
	shouldFlush := len(e.buffer) >= e.cfg.BatchSize
	e.mu.Unlock()

	if shouldFlush {
		go e.flush()
	}
	return true
}

// flush sends buffered events to the remote server.
func (e *GRPCExporter) flush() {
	e.mu.Lock()
	batch := e.buffer
	e.buffer = make([]*ExportEvent, 0, e.cfg.BatchSize)
	e.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	if err := e.sendBatch(batch); err != nil {
		log.Printf("[export] gRPC send error: %v (queued %d events)", err, len(batch))
		// Re-queue for retry
		e.mu.Lock()
		e.buffer = append(e.buffer, batch...)
		e.mu.Unlock()
		return
	}

	e.totalSent += int64(len(batch))
	log.Printf("[export] sent %d events to %s (total: %d)",
		len(batch), e.cfg.RemoteAddr, e.totalSent)
}

// sendBatch posts events to the remote server via HTTP.
// Uses JSON encoding over HTTP until a protobuf export service is defined.
func (e *GRPCExporter) sendBatch(batch []*ExportEvent) error {
	url := fmt.Sprintf("http://%s/api/v1/socket-events", e.cfg.RemoteAddr)
	data, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func (e *GRPCExporter) flushLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(e.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.flush()
		case <-e.stopCh:
			e.flush()
			return
		}
	}
}

// Stop gracefully shuts down the exporter.
func (e *GRPCExporter) Stop() {
	close(e.stopCh)
	e.wg.Wait()
}

// Stats returns export statistics.
func (e *GRPCExporter) Stats() map[string]interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]interface{}{
		"total_sent": e.totalSent,
		"buffer":     len(e.buffer),
		"batch_size": e.cfg.BatchSize,
		"remote":     e.cfg.RemoteAddr,
	}
}
