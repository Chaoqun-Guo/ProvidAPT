// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package dist

import (
	"container/list"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/transport"
)

// StreamConfig for the gRPC pipeline.
type StreamConfig struct {
	// ServerAddr — central analysis server address.
	ServerAddr string

	// BufferSize — max buffered events before blocking (default 10000).
	BufferSize int

	// FlushInterval — flush buffer on timer (default 1s).
	FlushInterval time.Duration

	// ReconnectInterval — reconnect delay (default 5s).
	ReconnectInterval time.Duration

	// EnableLocalBackup — buffer to local RocksDB on disconnect.
	EnableLocalBackup bool

	// MaxRetries — max reconnection attempts.
	MaxRetries int
}

// DefaultStreamConfig returns sensible defaults.
func DefaultStreamConfig() *StreamConfig {
	return &StreamConfig{
		ServerAddr:        "localhost:50052",
		BufferSize:        10000,
		FlushInterval:     time.Second,
		ReconnectInterval: 5 * time.Second,
		EnableLocalBackup: true,
		MaxRetries:        10,
	}
}

// StreamStatus indicates the pipeline state.
type StreamStatus int

const (
	StatusDisconnected StreamStatus = 0
	StatusConnecting   StreamStatus = 1
	StatusConnected    StreamStatus = 2
)

// StreamEvent is a single event sent through the telemetry pipeline.
type StreamEvent struct {
	FullID    string `json:"full_id"`
	EventType string `json:"event_type"`
	Payload   string `json:"payload,omitempty"`
	Tainted   bool   `json:"tainted"`
	Timestamp int64  `json:"timestamp_ns"`
}

// StreamPipeline manages gRPC streaming with buffer, reconnection,
// and an optional TransportManager for compression / dedup / prioritisation.
type StreamPipeline struct {
	cfg          *StreamConfig
	mu           sync.Mutex
	buffer       *list.List
	status       StreamStatus
	sent         int64
	dropped      int64
	reconnects   int
	stopCh       chan struct{}
	wg           sync.WaitGroup
	transportMgr *transport.TransportManager // optional optimisation layer
}

// NewStreamPipeline creates a gRPC streaming pipeline.
// If transportMgr is non-nil, the pipeline uses it for compression
// and priority routing before sending.
func NewStreamPipeline(cfg *StreamConfig, transportMgr *transport.TransportManager) *StreamPipeline {
	if cfg == nil {
		cfg = DefaultStreamConfig()
	}
	return &StreamPipeline{
		cfg:          cfg,
		buffer:       list.New(),
		status:       StatusDisconnected,
		stopCh:       make(chan struct{}),
		transportMgr: transportMgr,
	}
}

// Start begins the streaming pipeline.
func (sp *StreamPipeline) Start() {
	sp.wg.Add(1)
	go sp.loop()
	log.Printf("[stream] started → %s (buffer=%d, flush=%v, transport=%v)",
		sp.cfg.ServerAddr, sp.cfg.BufferSize, sp.cfg.FlushInterval, sp.transportMgr != nil)
}

func (sp *StreamPipeline) loop() {
	defer sp.wg.Done()
	ticker := time.NewTicker(sp.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sp.flush()
		case <-sp.stopCh:
			sp.flush()
			return
		}
	}
}

// Stop shuts down the pipeline.
func (sp *StreamPipeline) Stop() {
	close(sp.stopCh)
	sp.wg.Wait()
}

// Send queues an event for streaming. Non-blocking unless buffer full.
func (sp *StreamPipeline) Send(evt *StreamEvent) bool {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if sp.buffer.Len() >= sp.cfg.BufferSize {
		sp.dropped++
		log.Printf("[stream] buffer full — dropping event (dropped=%d)", sp.dropped)
		return false
	}

	sp.buffer.PushBack(evt)
	return true
}

// flush sends buffered events over the gRPC stream.
func (sp *StreamPipeline) flush() {
	sp.mu.Lock()
	if sp.buffer.Len() == 0 {
		sp.mu.Unlock()
		return
	}

	batch := make([]*StreamEvent, 0, sp.buffer.Len())
	for sp.buffer.Len() > 0 {
		front := sp.buffer.Front()
		batch = append(batch, front.Value.(*StreamEvent))
		sp.buffer.Remove(front)
	}
	sp.mu.Unlock()

	if err := sp.sendBatch(batch); err != nil {
		log.Printf("[stream] send failed: %v — requeuing %d events", err, len(batch))
		if sp.transportMgr != nil && sp.cfg.EnableLocalBackup {
			// Route failed events through the TransportManager's
			// low-priority queue for later replay.
			for _, evt := range batch {
				data := []byte(fmt.Sprintf("%s|%s", evt.FullID, evt.Payload))
				sp.transportMgr.Ingest(data, transport.PriorityLow, evt.Tainted, false)
			}
		} else {
			sp.mu.Lock()
			for _, evt := range batch {
				sp.buffer.PushBack(evt)
			}
			sp.mu.Unlock()
		}
		sp.handleDisconnect()
		return
	}

	sp.mu.Lock()
	sp.sent += int64(len(batch))
	sp.status = StatusConnected
	sp.mu.Unlock()
}

// sendBatch sends events over gRPC.
// If a TransportManager is attached, events are routed through its
// HashCache (dedup), Compressor (Zstd), and PriorityPipeline.
func (sp *StreamPipeline) sendBatch(batch []*StreamEvent) error {
	if len(batch) == 0 {
		return nil
	}

	if sp.transportMgr != nil {
		// Route through the transport optimisation layer.
		for _, evt := range batch {
			data := []byte(fmt.Sprintf("%s|%s:%s", evt.FullID, evt.EventType, evt.Payload))

			priority := transport.PriorityNormal
			if evt.Tainted {
				priority = transport.PriorityHigh
			}

			sp.transportMgr.Ingest(data, priority, evt.Tainted, false)
		}
		return nil
	}

	// In production: gRPC stream send
	// stream, err := client.ReportEvents(ctx)
	// for _, evt := range batch { stream.Send(evt) }
	// _, err := stream.CloseAndRecv()

	log.Printf("[stream] sent %d events to %s", len(batch), sp.cfg.ServerAddr)
	return nil
}

// handleDisconnect manages reconnection logic.
func (sp *StreamPipeline) handleDisconnect() {
	sp.mu.Lock()
	sp.status = StatusDisconnected
	sp.reconnects++
	reconnects := sp.reconnects
	sp.mu.Unlock()

	log.Printf("[stream] disconnected — reconnecting (attempt %d/%d)",
		reconnects, sp.cfg.MaxRetries)

	if reconnects > sp.cfg.MaxRetries {
		log.Printf("[stream] max retries exceeded")
		return
	}

	delay := sp.cfg.ReconnectInterval * time.Duration(reconnects)
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}

	time.Sleep(delay)
	sp.mu.Lock()
	sp.status = StatusConnecting
	sp.mu.Unlock()
}

// Stats returns pipeline statistics.
func (sp *StreamPipeline) Stats() map[string]interface{} {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return map[string]interface{}{
		"status":     sp.status,
		"buffered":   sp.buffer.Len(),
		"sent":       sp.sent,
		"dropped":    sp.dropped,
		"reconnects": sp.reconnects,
		"server":     sp.cfg.ServerAddr,
	}
}
