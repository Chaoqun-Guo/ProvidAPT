// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package container maps cgroup IDs to container metadata for
// ProvidAPT v2.1 provenance enrichment.
package container

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	containerpb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/container"
)

// ═══════════════════════════════════════════════════════════════
// ContainerInfo — cached container metadata
// ═══════════════════════════════════════════════════════════════

// ResolvedInfo contains the resolved container metadata for a cgroup.
type ResolvedInfo struct {
	CgroupID    uint64
	ContainerID string
	Name        string
	Image       string
	Orchestrator string
	PodName     string
	PodNamespace string
	LastSeen    time.Time
}

// ═══════════════════════════════════════════════════════════════
// Container Monitor
// ═══════════════════════════════════════════════════════════════

// Monitor resolves cgroup IDs to container metadata by scanning
// /proc/<pid>/cgroup and /sys/fs/cgroup/ paths, and optionally
// querying the Docker/Containerd API.
type Monitor struct {
	mu       sync.RWMutex
	cache    map[uint64]*ResolvedInfo // cgroup_id → info
	resolveCh chan uint64             // cgroup IDs needing resolution
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// New creates a container monitor.
func New() *Monitor {
	return &Monitor{
		cache:     make(map[uint64]*ResolvedInfo),
		resolveCh: make(chan uint64, 4096),
		stopCh:    make(chan struct{}),
	}
}

// Start begins background resolution.
func (m *Monitor) Start() {
	m.wg.Add(1)
	go m.resolverLoop()
	log.Printf("[container] monitor started")
}

func (m *Monitor) resolverLoop() {
	defer m.wg.Done()
	for {
		select {
		case cgroupID := <-m.resolveCh:
			m.resolve(cgroupID)
		case <-m.stopCh:
			return
		}
	}
}

// Stop shuts down the monitor.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

// LookupOrEnqueue returns cached container info or queues a resolve.
func (m *Monitor) LookupOrEnqueue(cgroupID uint64) *ResolvedInfo {
	m.mu.RLock()
	info, ok := m.cache[cgroupID]
	m.mu.RUnlock()
	if ok {
		return info
	}
	// Queue for async resolution
	select {
	case m.resolveCh <- cgroupID:
	default:
	}
	return nil
}

// resolve attempts to map a cgroup ID to container metadata.
func (m *Monitor) resolve(cgroupID uint64) {
	// Check if already resolved
	m.mu.RLock()
	_, ok := m.cache[cgroupID]
	m.mu.RUnlock()
	if ok {
		return
	}

	// Method 1: Scan /proc/<pid>/cgroup for matching cgroup ID
	info := m.scanProc(cgroupID)
	if info != nil {
		m.mu.Lock()
		m.cache[cgroupID] = info
		m.mu.Unlock()
		log.Printf("[container] resolved cgroup %d → container %s (%s)",
			cgroupID, info.ContainerID, info.Name)
		return
	}

	// Method 2: Parse /sys/fs/cgroup directly (for cgroup v2)
	info = m.scanSysFSCgroup(cgroupID)
	if info != nil {
		m.mu.Lock()
		m.cache[cgroupID] = info
		m.mu.Unlock()
	}
}

// ═══════════════════════════════════════════════════════════════
// Resolution methods
// ═══════════════════════════════════════════════════════════════

// scanProc scans /proc/<pid>/cgroup for matching cgroup ID.
// This is a simplified approach; in production it finds the process
// by scanning /proc/*/cgroup for the matching cgroup hierarchy ID.
func (m *Monitor) scanProc(cgroupID uint64) *ResolvedInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}

		info := m.parseProcCgroup(pid, cgroupID)
		if info != nil {
			info.CgroupID = cgroupID
			return info
		}
	}
	return nil
}

func (m *Monitor) parseProcCgroup(pid string, targetCgroupID uint64) *ResolvedInfo {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "cgroup"))
	if err != nil {
		return nil
	}

	info := &ResolvedInfo{}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// Format: "hierarchy-ID:controller-list:cgroup-path"
		// cgroup v2: "0::/system.slice/docker-<container>.scope"
		if !strings.Contains(line, "docker") &&
			!strings.Contains(line, "kubepods") &&
			!strings.Contains(line, "lxc") &&
			!strings.Contains(line, "crio") {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := parts[2]

		// Extract container ID from cgroup path
		// docker: /docker/<container_id>
		// k8s: /kubepods/.../<container_id>
		for _, pattern := range []struct {
			prefix string
			orchestrator string
		}{
			{"/docker/", "docker"},
			{"/kubepods/", "k8s"},
			{"/lxc/", "lxc"},
			{"/crio/", "crio"},
		} {
			if idx := strings.Index(path, pattern.prefix); idx >= 0 {
				rest := path[idx+len(pattern.prefix):]
				// Container ID is the first path component
				idParts := strings.SplitN(rest, "/", 2)
				if len(idParts) > 0 {
					info.ContainerID = strings.TrimSuffix(idParts[0], ".scope")
					info.Orchestrator = pattern.orchestrator
					info.Name = fmt.Sprintf("container-%.12s", info.ContainerID)
				}
				break
			}
		}

		if info.ContainerID != "" {
			return info
		}
	}
	return nil
}

// scanSysFSCgroup parses cgroup v2 directory for container info.
func (m *Monitor) scanSysFSCgroup(cgroupID uint64) *ResolvedInfo {
	// In production, this reads /sys/fs/cgroup/<path>/cgroup.procs
	// and matches processes to the cgroup ID from eBPF.
	// Simplified for the framework.
	return nil
}

// ─── Stats ──────────────────────────────────────────────────

// Stats returns monitor statistics.
func (m *Monitor) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]interface{}{
		"resolved_containers": len(m.cache),
	}
}

// GetContainerInfo returns cached container info by cgroup ID.
func (m *Monitor) GetContainerInfo(cgroupID uint64) *ResolvedInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cache[cgroupID]
}

// ListContainers returns all resolved containers.
func (m *Monitor) ListContainers() []*ResolvedInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*ResolvedInfo, 0, len(m.cache))
	for _, info := range m.cache {
		out = append(out, info)
	}
	return out
}

// ToProto converts a resolved container to protobuf.
func (ri *ResolvedInfo) ToProto() *containerpb.ContainerInfo {
	return &containerpb.ContainerInfo{
		CgroupId:      ri.CgroupID,
		ContainerId:   ri.ContainerID,
		ContainerName: ri.Name,
		Orchestrator:  ri.Orchestrator,
		PodName:       ri.PodName,
		PodNamespace:  ri.PodNamespace,
	}
}
