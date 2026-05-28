package appsync

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Request ID tracker
//
// Correlates application-layer request IDs with kernel TIDs.
// The BPF uprobe captures the request context and stores it in
// a BPF map keyed by TID.  The userspace side reads this map
// when processing syscall events and attaches the request ID
// to the provenance nodes.
// ═══════════════════════════════════════════════════════════════

// RequestInfo holds the application context for a thread.
type RequestInfo struct {
	TID        uint32    `json:"tid"`
	PID        uint32    `json:"pid"`
	RequestID  string    `json:"request_id"`  // extracted trace ID
	Method     string    `json:"method"`      // HTTP: GET, POST
	Path       string    `json:"path"`        // HTTP: /admin/config
	Query      string    `json:"query,omitempty"` // SQL query, etc.
	AppName    string    `json:"app_name"`
	StartTime  time.Time `json:"start_time"`
}

// RequestTracker maintains the mapping between TIDs and request IDs.
// In production, this is backed by a BPF map; for the framework we
// implement the userspace correlation logic.
type RequestTracker struct {
	mu       sync.RWMutex
	active   map[uint32]*RequestInfo // TID → request
	history  []*RequestInfo          // completed requests
	maxKeep  int                     // max history entries
}

// NewRequestTracker creates a request tracker.
func NewRequestTracker() *RequestTracker {
	return &RequestTracker{
		active:  make(map[uint32]*RequestInfo),
		maxKeep: 10000,
	}
}

// StartRequest is called when a uprobe entry fires.
func (rt *RequestTracker) StartRequest(tid, pid uint32, appName, requestID, method, path string) {
	info := &RequestInfo{
		TID:       tid,
		PID:       pid,
		RequestID: requestID,
		Method:    method,
		Path:      path,
		AppName:   appName,
		StartTime: time.Now(),
	}

	rt.mu.Lock()
	rt.active[tid] = info
	rt.mu.Unlock()

	log.Printf("[appsync] request start: tid=%d pid=%d [%s] %s %s (req=%s)",
		tid, pid, appName, method, path, requestID)
}

// EndRequest is called when a uprobe return fires.
func (rt *RequestTracker) EndRequest(tid uint32) {
	rt.mu.Lock()
	info, ok := rt.active[tid]
	if ok {
		delete(rt.active, tid)
		rt.history = append(rt.history, info)
		if len(rt.history) > rt.maxKeep {
			rt.history = rt.history[len(rt.history)-rt.maxKeep:]
		}
	}
	rt.mu.Unlock()

	if ok {
		log.Printf("[appsync] request end: tid=%d [%s] %s %s (duration=%v)",
			tid, info.AppName, info.Method, info.Path, time.Since(info.StartTime))
	}
}

// GetRequest returns the active request for a TID, if any.
func (rt *RequestTracker) GetRequest(tid uint32) *RequestInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.active[tid]
}

// GetOrCreateRequestID returns a request ID for a TID, generating one if needed.
func (rt *RequestTracker) GetOrCreateRequestID(tid, pid uint32, comm string) string {
	info := rt.GetRequest(tid)
	if info != nil && info.RequestID != "" {
		return info.RequestID
	}
	// Generate a synthetic request ID based on process info
	return fmt.Sprintf("sys:%s:%d", comm, pid)
}

// ActiveCount returns the number of in-flight requests.
func (rt *RequestTracker) ActiveCount() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return len(rt.active)
}

// RequestCount returns total tracked history entries.
func (rt *RequestTracker) RequestCount() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return len(rt.history)
}
