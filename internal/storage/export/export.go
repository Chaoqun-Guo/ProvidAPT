// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Client — sends telemetry to central server
// ═══════════════════════════════════════════════════════════════

// ClientConfig for the gRPC/HTTP export client.
type ClientConfig struct {
	ServerAddr  string        // central server address
	AgentID     string        // this agent's unique ID
	BatchSize   int           // events per batch (default 100)
	FlushEvery  time.Duration // flush interval (default 10s)
	EnableHTTP  bool          // use HTTP instead of gRPC
}

// Client handles exporting events to the central server.
type Client struct {
	cfg    ClientConfig
	host   string
	buffer []*SocketEvent
	stopCh chan struct{}
}

// NewClient creates an export client.
func NewClient(cfg ClientConfig) *Client {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 10 * time.Second
	}
	host, _ := os.Hostname()
	if cfg.AgentID == "" {
		cfg.AgentID = host
	}

	return &Client{
		cfg:    cfg,
		host:   host,
		buffer: make([]*SocketEvent, 0, cfg.BatchSize),
		stopCh: make(chan struct{}),
	}
}

// Start begins the background flush goroutine.
func (c *Client) Start() {
	go c.loop()
	log.Printf("[export] client started → %s (agent=%s, batch=%d, interval=%v)",
		c.cfg.ServerAddr, c.cfg.AgentID, c.cfg.BatchSize, c.cfg.FlushEvery)
}

// ReportSocketEvent queues a socket event for export.
func (c *Client) ReportSocketEvent(evt *SocketEvent) {
	evt.AgentID = c.cfg.AgentID
	evt.Hostname = c.host

	c.buffer = append(c.buffer, evt)
	if len(c.buffer) >= c.cfg.BatchSize {
		c.flush()
	}
}

// flush sends buffered events to the server.
func (c *Client) flush() {
	if len(c.buffer) == 0 {
		return
	}
	batch := c.buffer
	c.buffer = make([]*SocketEvent, 0, c.cfg.BatchSize)

	if err := c.sendBatch(batch); err != nil {
		log.Printf("[export] send error: %v (queued %d events)", err, len(batch))
		// Re-queue for retry
		c.buffer = append(c.buffer, batch...)
	}
}

func (c *Client) sendBatch(batch []*SocketEvent) error {
	url := c.cfg.ServerAddr + "/api/v1/socket-events"
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

func (c *Client) loop() {
	ticker := time.NewTicker(c.cfg.FlushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.flush()
		case <-c.stopCh:
			c.flush()
			return
		}
	}
}

// Stop gracefully shuts down the client.
func (c *Client) Stop() {
	close(c.stopCh)
	log.Printf("[export] client stopped")
}
