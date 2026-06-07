// Package client provides a Go client for the ProvidAPT REST API.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
)

// Client is a ProvidAPT API client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// New creates a new ProvidAPT API client.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey sets the API key for authentication.
func WithAPIKey(key string) Option {
	return func(c *Client) {
		c.apiKey = key
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// ── Internal request helpers ─────────────────────────────────

func (c *Client) get(path string, dst interface{}) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	return c.do(req, dst)
}

func (c *Client) post(path string, body, dst interface{}) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return fmt.Errorf("encode body: %w", err)
		}
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	return c.do(req, dst)
}

func (c *Client) do(req *http.Request, dst interface{}) error {
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	if dst != nil {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// ── API methods ──────────────────────────────────────────────

// Status returns daemon status information.
func (c *Client) Status() (*StatusResponse, error) {
	var resp StatusResponse
	err := c.get("/api/v1/status", &resp)
	return &resp, err
}

// StatusResponse represents the daemon status.
type StatusResponse struct {
	Status        string `json:"status"`
	Nodes         int    `json:"nodes"`
	Edges         int    `json:"edges"`
	Timestamp     string `json:"timestamp"`
	Health        string `json:"health,omitempty"`
	UptimeSeconds int64  `json:"uptime_seconds,omitempty"`
	MemoryBytes   uint64 `json:"memory_bytes,omitempty"`
}

// Health returns daemon health status.
func (c *Client) Health() (*HealthResponse, error) {
	var resp HealthResponse
	err := c.get("/health", &resp)
	return &resp, err
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status          string `json:"status"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
	EbpfCollector   bool   `json:"ebpf_collector"`
	PipelineHealthy bool   `json:"pipeline_healthy"`
	StoreHealthy    bool   `json:"store_healthy"`
	EventsIngested  uint64 `json:"events_ingested"`
	EventsDropped   uint64 `json:"events_dropped"`
	MemoryBytes     uint64 `json:"memory_bytes"`
	Version         string `json:"version"`
}

// ExportGraph exports the provenance graph in Cytoscape format.
func (c *Client) ExportGraph(pid string) (*GraphResponse, error) {
	path := "/api/v1/graph/export"
	if pid != "" {
		path += "?pid=" + pid
	}
	var resp GraphResponse
	err := c.get(path, &resp)
	return &resp, err
}

// GraphResponse represents a graph export response.
type GraphResponse struct {
	Data     GraphMeta      `json:"data"`
	Elements []GraphElement `json:"elements"`
}

// GraphMeta contains graph metadata.
type GraphMeta struct {
	Generated string `json:"generated"`
	NodeCount int    `json:"node_count"`
	EdgeCount int    `json:"edge_count"`
}

// GraphElement is a graph node or edge.
type GraphElement struct {
	Group string        `json:"group"`
	Data  ElementData   `json:"data"`
}

// ElementData contains element-specific data.
type ElementData struct {
	ID       string `json:"id,omitempty"`
	Source   string `json:"source,omitempty"`
	Target   string `json:"target,omitempty"`
	Label    string `json:"label,omitempty"`
	NodeType string `json:"type,omitempty"`
}

// TraceNode traces backward or forward from a node.
func (c *Client) TraceNode(nodeID, direction string, depth int) (*GraphResponse, error) {
	path := fmt.Sprintf("/api/v1/graph/node/%s/%s?depth=%d", nodeID, direction, depth)
	var resp GraphResponse
	err := c.get(path, &resp)
	return &resp, err
}

// Alerts returns current alerts.
func (c *Client) Alerts() (*AlertsResponse, error) {
	var resp AlertsResponse
	err := c.get("/api/v1/alerts", &resp)
	return &resp, err
}

// AlertsResponse represents the alerts response.
type AlertsResponse struct {
	Alerts []Alert `json:"alerts"`
	Count  int     `json:"count"`
}

// Alert represents a single alert.
type Alert struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
}

// Reload triggers a daemon config reload.
func (c *Client) Reload() error {
	return c.post("/api/v1/admin/reload", nil, nil)
}

// RecentEvents returns the most recent events.
func (c *Client) RecentEvents() ([]Event, error) {
	var resp []Event
	err := c.get("/api/v1/events/recent", &resp)
	return resp, err
}

// Event is a provenance event.
type Event struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	PID     uint32 `json:"pid"`
	Comm    string `json:"comm"`
	Path    string `json:"path,omitempty"`
	Time    string `json:"time"`
}
