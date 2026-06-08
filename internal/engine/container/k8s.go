// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package container — Kubernetes-aware container metadata resolution.
//
// Provides:
//   1. CRI listener — watches containerd socket for pod events
//   2. Cgroup→PodName/Namespace/Image mapping table
//   3. K8s API integration for rich metadata
package container

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Pod metadata
// ═══════════════════════════════════════════════════════════════

// PodInfo holds K8s pod metadata resolved from a cgroup ID.
type PodInfo struct {
	CgroupID    uint64 `json:"cgroup_id"`
	PodName     string `json:"pod_name"`
	PodUID      string `json:"pod_uid"`
	Namespace   string `json:"namespace"`
	ContainerID string `json:"container_id"`
	ContainerName string `json:"container_name"`
	Image       string `json:"image"`
	NodeName    string `json:"node_name"`
	Labels      map[string]string `json:"labels,omitempty"`

	// Security context
	ServiceAccount string `json:"service_account,omitempty"`
	Privileged     bool   `json:"privileged"`
	HostNetwork    bool   `json:"host_network"`

	LastSeen time.Time `json:"last_seen"`
}

// ═══════════════════════════════════════════════════════════════
// K8sListener
// ═══════════════════════════════════════════════════════════════

// K8sListener maintains a real-time mapping of cgroup IDs to
// Kubernetes pod metadata by monitoring:
//   - /var/run/containerd/containerd.sock (CRI)
//   - /var/log/pods/ (K8s pod log directory)
//   - /proc/*/cgroup (process-level cgroup scanning)
//   - K8s API server (optional, for rich metadata)
type K8sListener struct {
	mu           sync.RWMutex
	podMap       map[uint64]*PodInfo // cgroupID → pod info
	nsMap        map[string]bool     // known namespaces
	containerMeta map[string]*containerMeta // namespace/pod/container → image+podUID
	enabled      bool

	stopCh  chan struct{}
	wg      sync.WaitGroup
}

type containerMeta struct {
	Image  string
	PodUID string
}

// NewK8sListener creates a K8s-aware container listener.
func NewK8sListener() *K8sListener {
	return &K8sListener{
		podMap:        make(map[uint64]*PodInfo),
		nsMap:         make(map[string]bool),
		containerMeta: make(map[string]*containerMeta),
		stopCh:        make(chan struct{}),
	}
}

// Start begins background monitoring.
func (kl *K8sListener) Start() {
	kl.enabled = true
	kl.wg.Add(2)
	go kl.podLogScanner()
	go kl.procCgroupScanner()
	log.Printf("[k8s] listener started")
}

// Stop shuts down the listener.
func (kl *K8sListener) Stop() {
	close(kl.stopCh)
	kl.wg.Wait()
}

// IsEnabled returns true if K8s metadata resolution is active.
func (kl *K8sListener) IsEnabled() bool {
	return kl.enabled
}

// ─── Resolution methods ─────────────────────────────────────

// ResolveByCgroupID returns pod info for a cgroup ID.
func (kl *K8sListener) ResolveByCgroupID(cgroupID uint64) *PodInfo {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return kl.podMap[cgroupID]
}

// ResolveByPodName returns all containers in a pod.
func (kl *K8sListener) ResolveByPodName(podName, namespace string) []*PodInfo {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	var result []*PodInfo
	for _, pi := range kl.podMap {
		if pi.PodName == podName && pi.Namespace == namespace {
			result = append(result, pi)
		}
	}
	return result
}

// ─── Scanner: /var/log/pods ─────────────────────────────────

// podLogScanner watches /var/log/pods/ for pod metadata.
// K8s writes pod log directories with format: <namespace>_<pod>_<uid>/
func (kl *K8sListener) podLogScanner() {
	defer kl.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial scan
	kl.scanPodLogs()

	for {
		select {
		case <-ticker.C:
			kl.scanPodLogs()
		case <-kl.stopCh:
			return
		}
	}
}

func (kl *K8sListener) scanPodLogs() {
	podLogDir := "/var/log/pods"
	entries, err := os.ReadDir(podLogDir)
	if err != nil {
		return // not a K8s node or no permissions
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Format: <namespace>_<pod>_<pod-uid>
		parts := strings.SplitN(entry.Name(), "_", 3)
		if len(parts) < 2 {
			continue
		}
		namespace := parts[0]
		podName := parts[1]
		podUID := ""
		if len(parts) >= 3 {
			podUID = parts[2]
		}

		// Scan container directories within the pod
		containerDir := filepath.Join(podLogDir, entry.Name())
		containers, err := os.ReadDir(containerDir)
		if err != nil {
			continue
		}

		for _, c := range containers {
			if !c.IsDir() {
				continue
			}
			containerName := c.Name()

			// Read metadata if available
			metaPath := filepath.Join(containerDir, containerName, "metadata.json")
			kl.registerPod(namespace, podName, podUID, containerName, metaPath)
		}
	}
}

func (kl *K8sListener) registerPod(namespace, podName, podUID, containerName, metaPath string) {
	image := ""
	if data, err := os.ReadFile(metaPath); err == nil {
		var meta struct {
			Image string `json:"image"`
		}
		json.Unmarshal(data, &meta)
		image = meta.Image
	}

	kl.mu.Lock()
	kl.nsMap[namespace] = true
	metaKey := namespace + "/" + podName + "/" + containerName
	kl.containerMeta[metaKey] = &containerMeta{Image: image, PodUID: podUID}
	kl.mu.Unlock()
}

// ─── Scanner: /proc/*/cgroup ────────────────────────────────

// procCgroupScanner periodically scans /proc for cgroup paths.
func (kl *K8sListener) procCgroupScanner() {
	defer kl.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			kl.scanProcCgroups()
		case <-kl.stopCh:
			return
		}
	}
}

func (kl *K8sListener) scanProcCgroups() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}

		data, err := os.ReadFile(filepath.Join("/proc", pid, "cgroup"))
		if err != nil {
			continue
		}

		kl.parseAndMap(pid, string(data))
	}
}

func (kl *K8sListener) parseAndMap(pid, cgroupData string) {
	for _, line := range strings.Split(cgroupData, "\n") {
		// cgroup v2 format: "0::/kubepods/burstable/pod-<uid>/<container-id>"
		if !strings.Contains(line, "kubepods") &&
			!strings.Contains(line, "pod") {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := parts[2]

		// Parse K8s cgroup path:
		// /kubepods/burstable/pod-<pod-uid>/<container-id>
		pathParts := strings.Split(strings.Trim(path, "/"), "/")
		if len(pathParts) < 3 {
			continue
		}

		var podUID, containerID string
		for _, pp := range pathParts {
			if strings.HasPrefix(pp, "pod-") {
				podUID = strings.TrimPrefix(pp, "pod-")
			} else if len(pp) == 64 && isHex(pp) {
				containerID = pp
			}
		}

		// Resolve pod name from UID via K8s API
		podName := kl.resolvePodName(podUID)

		// Look up container metadata (image) from pod log scan
		kl.mu.RLock()
		img := kl.lookupContainerImage(podUID, podName, containerID)
		kl.mu.RUnlock()

		kl.mu.Lock()
		kl.podMap[uint64(parsePID(pid))] = &PodInfo{
			PodName:      podName,
			PodUID:       podUID,
			ContainerID:  containerID,
			Image:        img,
			LastSeen:     time.Now(),
		}
		kl.mu.Unlock()

		log.Printf("[k8s] mapped PID %s → pod=%s uid=%s image=%s container=%.12s",
			pid, podName, podUID, img, containerID)
		break
	}
}

// resolvePodName attempts to resolve pod name from UID via K8s API
// using in-cluster service account credentials with proper TLS.
func (kl *K8sListener) resolvePodName(podUID string) string {
	tokenData, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return syntheticPodName(podUID)
	}
	token := strings.TrimSpace(string(tokenData))

	apiServer := os.Getenv("KUBERNETES_SERVICE_HOST")
	apiPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if apiServer == "" {
		return syntheticPodName(podUID)
	}
	if apiPort == "" {
		apiPort = "443"
	}

	// Load CA cert for proper TLS verification
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return syntheticPodName(podUID)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return syntheticPodName(podUID)
	}

	url := fmt.Sprintf("https://%s/api/v1/pods?fieldSelector=metadata.uid%%3D%s",
		net.JoinHostPort(apiServer, apiPort), podUID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return syntheticPodName(podUID)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caCertPool,
			ServerName: fmt.Sprintf("kubernetes.default.svc.%s", os.Getenv("KUBERNETES_SERVICE_HOST")),
		},
	}
	// Override ServerName when the env is a hostname
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); net.ParseIP(host) != nil {
		tr.TLSClientConfig.ServerName = "kubernetes.default.svc"
	} else {
		tr.TLSClientConfig.ServerName = host
	}

	cli := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return syntheticPodName(podUID)
	}
	defer resp.Body.Close()

	var podList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&podList); err == nil && len(podList.Items) > 0 {
		return podList.Items[0].Metadata.Name
	}
	return syntheticPodName(podUID)
}

// syntheticPodName returns a placeholder pod name derived from the UID.
func syntheticPodName(podUID string) string {
	if len(podUID) > 8 {
		podUID = podUID[:8]
	}
	return "pod-" + podUID
}

// lookupContainerImage searches containerMeta for the image matching a pod/container.
func (kl *K8sListener) lookupContainerImage(podUID, podName, containerID string) string {
	// Try matching by podUID first
	for metaKey, meta := range kl.containerMeta {
		if meta.PodUID == podUID {
			return meta.Image
		}
		// Fallback: match by podName in key (format: namespace/podName/containerName)
		parts := strings.SplitN(metaKey, "/", 3)
		if len(parts) >= 2 && parts[1] == podName {
			if len(parts) < 3 || strings.HasPrefix(containerID, parts[2]) {
				return meta.Image
			}
		}
	}
	return ""
}

// ─── Helpers ────────────────────────────────────────────────

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func parsePID(s string) int {
	var pid int
	fmt.Sscanf(s, "%d", &pid)
	return pid
}

// Stats returns listener statistics.
func (kl *K8sListener) Stats() map[string]interface{} {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return map[string]interface{}{
		"pods_mapped":  len(kl.podMap),
		"namespaces":   len(kl.nsMap),
		"enabled":      kl.enabled,
	}
}
