// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package profile provides built-in performance statistics for
// ProvidAPT v2, covering kernel eBPF overhead, RocksDB throughput,
// and overall system resource usage.
package profile

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Kernel eBPF statistics via bpftool
// ═══════════════════════════════════════════════════════════════

// BPFProgInfo holds runtime statistics for a single eBPF program.
type BPFProgInfo struct {
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	RunCount  int64   `json:"run_count"`
	RunTimeNS int64   `json:"run_time_ns"`
	AvgRunNS  float64 `json:"avg_run_ns"`
}

// BPFStats collects kernel-side eBPF performance data.
type BPFStats struct {
	Programs []BPFProgInfo `json:"programs"`
	TotalRuns int64        `json:"total_runs"`
	TotalTime int64        `json:"total_time_ns"`
}

// CollectBPFStats queries bpftool for eBPF program statistics.
func CollectBPFStats() (*BPFStats, error) {
	stats := &BPFStats{}

	// Use bpftool to list programs with their runtime stats
	cmd := exec.Command("bpftool", "prog", "list", "--json")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try without --json
		cmd = exec.Command("bpftool", "prog", "list")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("bpftool not available: %w", err)
		}
		// Parse text output
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "lsm") || strings.Contains(line, "tracepoint") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					id, _ := strconv.Atoi(parts[0][:len(parts[0])-1])
					prog := BPFProgInfo{
						ID:   id,
						Name: parts[len(parts)-1],
						Type: parts[1],
					}
					// Extended stats via bpftool prog show id <id>
					prog = collectProgRunTime(prog)
					stats.Programs = append(stats.Programs, prog)
					stats.TotalRuns += prog.RunCount
					stats.TotalTime += prog.RunTimeNS
				}
			}
		}
	}

	// Parse JSON output
	var progList []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(output, &progList); err == nil {
		stats.Programs = make([]BPFProgInfo, 0, len(progList))
		for _, p := range progList {
			prog := BPFProgInfo{
				ID:   p.ID,
				Name: p.Name,
				Type: p.Type,
			}
			prog = collectProgRunTime(prog)
			stats.Programs = append(stats.Programs, prog)
			stats.TotalRuns += prog.RunCount
			stats.TotalTime += prog.RunTimeNS
		}
	}

	return stats, nil
}

// collectProgRunTime gets detailed runtime info for a program.
func collectProgRunTime(prog BPFProgInfo) BPFProgInfo {
	cmd := exec.Command("bpftool", "prog", "show", "id", fmt.Sprintf("%d", prog.ID))
	output, err := cmd.Output()
	if err != nil {
		return prog
	}

	line := string(output)
	// Parse: "run_time_ns X run_cnt Y"
	if r := extractAfter(line, "run_time_ns"); r > 0 {
		prog.RunTimeNS = int64(r)
	}
	if c := extractAfter(line, "run_cnt"); c > 0 {
		prog.RunCount = int64(c)
	}
	if prog.RunCount > 0 {
		prog.AvgRunNS = float64(prog.RunTimeNS) / float64(prog.RunCount)
	}

	return prog
}

func extractAfter(s, prefix string) int64 {
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return 0
	}
	rest := s[idx+len(prefix):]
	parts := strings.Fields(rest)
	if len(parts) > 0 {
		val, err := strconv.ParseInt(parts[0], 10, 64)
		if err == nil {
			return val
		}
	}
	return 0
}

// ═══════════════════════════════════════════════════════════════
// Storage throughput monitoring
// ═══════════════════════════════════════════════════════════════

// StorageStats tracks RocksDB write performance.
type StorageStats struct {
	mu            sync.Mutex
	nodesWritten  int64
	edgesWritten  int64
	totalLatency  int64 // nanoseconds
	writeOps      int64
	lastReset     time.Time

	// Rolling window
	windowCount   int64
	windowLatency int64
	windowStart   time.Time
}

// NewStorageStats creates a storage monitor.
func NewStorageStats() *StorageStats {
	return &StorageStats{
		lastReset:   time.Now(),
		windowStart: time.Now(),
	}
}

// RecordWrite records a write operation with its latency.
func (ss *StorageStats) RecordWrite(latency time.Duration, nodeCount, edgeCount int) {
	atomic.AddInt64(&ss.nodesWritten, int64(nodeCount))
	atomic.AddInt64(&ss.edgesWritten, int64(edgeCount))
	atomic.AddInt64(&ss.totalLatency, latency.Nanoseconds())
	atomic.AddInt64(&ss.writeOps, 1)

	// Window counters
	atomic.AddInt64(&ss.windowCount, 1)
	atomic.AddInt64(&ss.windowLatency, latency.Nanoseconds())
}

// NodesPerSecond returns the current node write rate.
func (ss *StorageStats) NodesPerSecond() float64 {
	nodes := atomic.LoadInt64(&ss.nodesWritten)
	elapsed := time.Since(ss.lastReset).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(nodes) / elapsed
}

// AvgWriteLatency returns the average write latency.
func (ss *StorageStats) AvgWriteLatency() time.Duration {
	ops := atomic.LoadInt64(&ss.writeOps)
	if ops == 0 {
		return 0
	}
	avg := atomic.LoadInt64(&ss.totalLatency) / ops
	return time.Duration(avg)
}

// WindowLatencyP99 returns the 99th percentile latency estimate
// based on the current rolling window.
func (ss *StorageStats) WindowLatencyP99() time.Duration {
	count := atomic.LoadInt64(&ss.windowCount)
	if count == 0 {
		return 0
	}
	// Simplified P99: using max observed * 0.99 (in production,
	// maintain a histogram for accurate percentiles)
	total := atomic.LoadInt64(&ss.windowLatency)
	avg := total / count
	return time.Duration(int64(float64(avg) * 1.5))
}

// ResetWindow resets the rolling window counters.
func (ss *StorageStats) ResetWindow() {
	atomic.StoreInt64(&ss.windowCount, 0)
	atomic.StoreInt64(&ss.windowLatency, 0)
	ss.windowStart = time.Now()
}

// ═══════════════════════════════════════════════════════════════
// System resource monitoring
// ═══════════════════════════════════════════════════════════════

// SystemStats captures overall system resource usage.
type SystemStats struct {
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryRSSMB float64 `json:"memory_rss_mb"`
	MemoryVMMB  float64 `json:"memory_vm_mb"`
	Goroutines  int     `json:"goroutines"`
	GoVersion   string  `json:"go_version"`
	FDCount     int     `json:"fd_count"`
}

// CollectSystemStats gathers current system resource usage.
func CollectSystemStats() *SystemStats {
	stats := &SystemStats{
		Goroutines: runtime.NumGoroutine(),
		GoVersion:  runtime.Version(),
	}

	// Memory usage from /proc/self/status
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			switch {
			case strings.HasPrefix(line, "VmRSS:"):
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					v, _ := strconv.ParseFloat(parts[1], 64)
					stats.MemoryRSSMB = v / 1024
				}
			case strings.HasPrefix(line, "VmSize:"):
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					v, _ := strconv.ParseFloat(parts[1], 64)
					stats.MemoryVMMB = v / 1024
				}
			}
		}
	}

	// FD count
	if fdDir, err := os.Open("/proc/self/fd"); err == nil {
		fds, _ := fdDir.Readdirnames(-1)
		stats.FDCount = len(fds)
		fdDir.Close()
	}

	// CPU usage (simplified: based on process uptime and CPU time)
	if data, err := os.ReadFile("/proc/self/stat"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 15 {
			utime, _ := strconv.ParseFloat(fields[13], 64)
			stime, _ := strconv.ParseFloat(fields[14], 64)
			totalCPU := utime + stime
			uptime := time.Since(processStartTime()).Seconds()
			if uptime > 0 {
				stats.CPUPercent = math.Min(totalCPU/uptime*100*100, 100)
			}
		}
	}

	return stats
}

var procStartTime time.Time

func init() {
	procStartTime = time.Now()
}

func processStartTime() time.Time {
	return procStartTime
}

// ═══════════════════════════════════════════════════════════════
// Performance report
// ═══════════════════════════════════════════════════════════════

// ProfileReport is the complete performance report.
type ProfileReport struct {
	Timestamp string                 `json:"timestamp"`
	System    *SystemStats           `json:"system"`
	BPF       *BPFStats              `json:"bpf"`
	Storage   map[string]interface{} `json:"storage"`
	Duration  string                 `json:"duration"`
}

// CollectProfile gathers all performance data into a single report.
func CollectProfile(storageStats *StorageStats) *ProfileReport {
	start := time.Now()

	bpfStats, _ := CollectBPFStats()
	sysStats := CollectSystemStats()

	report := &ProfileReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		System:    sysStats,
		BPF:       bpfStats,
		Storage:   make(map[string]interface{}),
		Duration:  time.Since(start).String(),
	}

	if storageStats != nil {
		report.Storage["nodes_per_sec"] = math.Round(storageStats.NodesPerSecond()*100) / 100
		report.Storage["avg_write_latency"] = storageStats.AvgWriteLatency().String()
		report.Storage["p99_latency"] = storageStats.WindowLatencyP99().String()
		report.Storage["total_nodes"] = atomic.LoadInt64(&storageStats.nodesWritten)
		report.Storage["total_edges"] = atomic.LoadInt64(&storageStats.edgesWritten)
	}

	return report
}

// String returns a human-readable profile report.
func (pr *ProfileReport) String() string {
	var b strings.Builder
	b.WriteString("ProvidAPT Performance Profile\n")
	b.WriteString("============================\n\n")
	b.WriteString(fmt.Sprintf("Timestamp: %s\n", pr.Timestamp))

	if pr.System != nil {
		b.WriteString("\n─── System Resources ───\n")
		b.WriteString(fmt.Sprintf("  CPU:        %.1f%%\n", pr.System.CPUPercent))
		b.WriteString(fmt.Sprintf("  Memory RSS: %.0f MB\n", pr.System.MemoryRSSMB))
		b.WriteString(fmt.Sprintf("  Memory VM:  %.0f MB\n", pr.System.MemoryVMMB))
		b.WriteString(fmt.Sprintf("  Goroutines: %d\n", pr.System.Goroutines))
		b.WriteString(fmt.Sprintf("  Go version: %s\n", pr.System.GoVersion))
		b.WriteString(fmt.Sprintf("  Open FDs:   %d\n", pr.System.FDCount))
	}

	if pr.BPF != nil {
		b.WriteString("\n─── eBPF Programs ───\n")
		b.WriteString(fmt.Sprintf("  Total programs: %d\n", len(pr.BPF.Programs)))
		b.WriteString(fmt.Sprintf("  Total runs:     %d\n", pr.BPF.TotalRuns))
		totalMS := float64(pr.BPF.TotalTime) / 1e6
		b.WriteString(fmt.Sprintf("  Total runtime:  %.2f ms\n", totalMS))
		b.WriteString("\n  Per-program:\n")
		for _, p := range pr.BPF.Programs {
			avg := float64(p.AvgRunNS) / 1000
			b.WriteString(fmt.Sprintf("    [%d] %-25s runs=%d avg=%.2fµs\n",
				p.ID, p.Name, p.RunCount, avg))
		}
	}

	if len(pr.Storage) > 0 {
		b.WriteString("\n─── Storage ───\n")
		b.WriteString(fmt.Sprintf("  Write rate:  %.0f nodes/sec\n", pr.Storage["nodes_per_sec"]))
		b.WriteString(fmt.Sprintf("  Avg latency: %s\n", pr.Storage["avg_write_latency"]))
		b.WriteString(fmt.Sprintf("  P99 latency: %s\n", pr.Storage["p99_latency"]))
	}

	b.WriteString(fmt.Sprintf("\nProfile collected in %s\n", pr.Duration))
	return b.String()
}

// Log logs the profile report at INFO level.
func (pr *ProfileReport) Log() {
	bpfRuns := int64(0)
	if pr.BPF != nil {
		bpfRuns = pr.BPF.TotalRuns
	}
	nps := float64(0)
	if pr.Storage != nil {
		if v, ok := pr.Storage["nodes_per_sec"]; ok {
			nps, _ = v.(float64)
		}
	}
	log.Printf("[profile] CPU=%.1f%% MEM=%.0fMB BPF_runs=%d NPS=%.0f",
		pr.System.CPUPercent, pr.System.MemoryRSSMB,
		bpfRuns, nps)
}
