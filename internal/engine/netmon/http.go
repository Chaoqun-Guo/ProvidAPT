package netmon

import (
	"log"
	"strings"
	"sync"
)

// ═══════════════════════════════════════════════════════════════
// HTTP metadata extraction
// ═══════════════════════════════════════════════════════════════

// HTTPRequest captures key metadata from an HTTP request.
type HTTPRequest struct {
	Method      string `json:"method"`      // GET, POST, etc.
	Host        string `json:"host"`        // Host header
	Path        string `json:"path"`        // URL path
	UserAgent   string `json:"user_agent,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// HTTPTracker extracts and caches HTTP request metadata.
type HTTPTracker struct {
	mu      sync.Mutex
	bySocket map[SocketKey]*HTTPRequest // socket → HTTP metadata
}

// NewHTTPTracker creates an HTTP tracker.
func NewHTTPTracker() *HTTPTracker {
	return &HTTPTracker{
		bySocket: make(map[SocketKey]*HTTPRequest),
	}
}

// ParseHTTPRequest extracts HTTP metadata from a byte buffer.
// Handles both HTTP/1.1 and HTTP/2 (via pseudo-headers).
func ParseHTTPRequest(data []byte) *HTTPRequest {
	req := &HTTPRequest{}
	text := string(data)

	lines := strings.SplitN(text, "\r\n", 2)
	if len(lines) == 0 {
		return nil
	}

	// Parse request line: "GET /path HTTP/1.1"
	first := strings.Fields(lines[0])
	if len(first) >= 2 {
		req.Method = first[0]
		req.Path = first[1]
	}

	// Parse headers
	if len(lines) >= 2 {
		for _, header := range strings.Split(lines[1], "\r\n") {
			lower := strings.ToLower(header)
			switch {
			case strings.HasPrefix(lower, "host:"):
				req.Host = strings.TrimSpace(header[5:])
			case strings.HasPrefix(lower, "user-agent:"):
				req.UserAgent = strings.TrimSpace(header[11:])
			case strings.HasPrefix(lower, "content-type:"):
				req.ContentType = strings.TrimSpace(header[13:])
			}
		}
	}

	return req
}

// RecordRequest associates HTTP metadata with a socket connection.
func (ht *HTTPTracker) RecordRequest(key SocketKey, req *HTTPRequest) {
	if req == nil {
		return
	}
	ht.mu.Lock()
	ht.bySocket[key] = req
	ht.mu.Unlock()

	log.Printf("[http] %s %s %s (host=%s)", req.Method, req.Path, key, req.Host)
}

// GetRequest returns HTTP metadata for a socket.
func (ht *HTTPTracker) GetRequest(key SocketKey) *HTTPRequest {
	ht.mu.Lock()
	defer ht.mu.Unlock()
	return ht.bySocket[key]
}

// EnrichSocket attaches HTTP metadata to a socket state.
func (ht *HTTPTracker) EnrichSocket(key SocketKey, sock *SocketState) {
	req := ht.GetRequest(key)
	if req == nil {
		return
	}
	sock.HTTPHost = req.Host
	if req.Path != "" {
		sock.HTTPPath = req.Method + " " + req.Path
	}
}

// Stats returns HTTP tracker statistics.
func (ht *HTTPTracker) Stats() map[string]interface{} {
	ht.mu.Lock()
	defer ht.mu.Unlock()
	return map[string]interface{}{
		"tracked_requests": len(ht.bySocket),
	}
}
