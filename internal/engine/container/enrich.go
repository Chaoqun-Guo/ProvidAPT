// Package container — async enrichment of container metadata.
//
// Before data enters RocksDB, this module attaches K8s metadata
// (PodName, Namespace, Image) to each event using the cgroup ID
// resolved by the K8sListener.
package container

import (
	"sync"
)

// ═══════════════════════════════════════════════════════════════
// Enricher
// ═══════════════════════════════════════════════════════════════

// Enricher attaches K8s metadata to events before storage.
type Enricher struct {
	listener *K8sListener
	mu       sync.RWMutex
	cache    map[uint64]*EnrichedEvent // cgroupID → enriched event
}

// EnrichedEvent holds the original event plus K8s metadata.
type EnrichedEvent struct {
	// Original event fields (simplified)
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	Pathname   string `json:"pathname,omitempty"`
	EventType  uint32 `json:"event_type"`

	// Container context from eBPF
	CgroupID   uint64 `json:"cgroup_id"`

	// K8s metadata (enriched)
	PodName      string `json:"pod_name,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	ContainerID  string `json:"container_id,omitempty"`
	Image        string `json:"image,omitempty"`
}

// NewEnricher creates an enricher attached to a K8s listener.
func NewEnricher(listener *K8sListener) *Enricher {
	return &Enricher{
		listener: listener,
		cache:    make(map[uint64]*EnrichedEvent),
	}
}

// Enrich attaches K8s metadata using the cgroup ID.
// Returns the enriched event.  If no K8s metadata is available,
// returns the original fields with empty K8s fields.
func (e *Enricher) Enrich(pid uint32, comm, pathname string, eventType uint32, cgroupID uint64) *EnrichedEvent {
	evt := &EnrichedEvent{
		PID:       pid,
		Comm:      comm,
		Pathname:  pathname,
		EventType: eventType,
		CgroupID:  cgroupID,
	}

	// Resolve K8s metadata from cgroup ID
	if e.listener != nil {
		podInfo := e.listener.ResolveByCgroupID(cgroupID)
		if podInfo != nil {
			evt.PodName = podInfo.PodName
			evt.Namespace = podInfo.Namespace
			evt.ContainerID = podInfo.ContainerID
			evt.Image = podInfo.Image
		}
	}

	// Cache recent enrichments
	e.mu.Lock()
	e.cache[cgroupID] = evt
	if len(e.cache) > 10000 {
		// Trim old entries
		for k := range e.cache {
			delete(e.cache, k)
			break
		}
	}
	e.mu.Unlock()

	return evt
}

// GetCached returns a cached enriched event by cgroup ID.
func (e *Enricher) GetCached(cgroupID uint64) *EnrichedEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cache[cgroupID]
}

// PodLabel returns a human-readable pod label for the event.
func (ee *EnrichedEvent) PodLabel() string {
	if ee.PodName != "" {
		return ee.PodName
	}
	return "host"
}

// Key returns a composite key for multi-tenant isolation checks.
func (ee *EnrichedEvent) IsolationKey() string { return ee.Namespace + "/" + ee.PodName }
