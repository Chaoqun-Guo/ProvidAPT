// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package fold

import (
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Dynamic threshold — adjusts aggregation window based on CPU load
// ═══════════════════════════════════════════════════════════════

// ThrottleConfig controls the adaptive throttle behaviour.
type ThrottleConfig struct {
	// CPULow — below this CPU% uses minimum window (default 20.0).
	CPULow float64

	// CPUHigh — above this CPU% uses maximum window (default 80.0).
	CPUHigh float64

	// MinWindow — smallest aggregation window (default 100ms).
	MinWindow time.Duration

	// MaxWindow — largest aggregation window (default 5s).
	MaxWindow time.Duration

	// DefaultWindow — starting window (default 1s).
	DefaultWindow time.Duration

	// CheckInterval — how often to check CPU (default 5s).
	CheckInterval time.Duration
}

// DefaultThrottleConfig returns sensible defaults.
func DefaultThrottleConfig() *ThrottleConfig {
	return &ThrottleConfig{
		CPULow:        20.0,
		CPUHigh:       80.0,
		MinWindow:     100 * time.Millisecond,
		MaxWindow:     5 * time.Second,
		DefaultWindow: time.Second,
		CheckInterval: 5 * time.Second,
	}
}

// ThrottleController adjusts aggregation thresholds based on CPU load.
type ThrottleController struct {
	cfg       *ThrottleConfig
	agg       *IOAggregator
	filter    *RedundancyFilter
	mu        sync.Mutex
	currentWindow time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewThrottleController creates a throttle controller.
func NewThrottleController(cfg *ThrottleConfig, agg *IOAggregator, filter *RedundancyFilter) *ThrottleController {
	if cfg == nil {
		cfg = DefaultThrottleConfig()
	}
	return &ThrottleController{
		cfg:           cfg,
		agg:           agg,
		filter:        filter,
		currentWindow: cfg.DefaultWindow,
		stopCh:        make(chan struct{}),
	}
}

// Start begins the CPU monitoring loop.
func (tc *ThrottleController) Start() {
	tc.wg.Add(1)
	go tc.loop()
	log.Printf("[throttle] started (low=%.0f%%, high=%.0f%%, window=[%v, %v])",
		tc.cfg.CPULow, tc.cfg.CPUHigh, tc.cfg.MinWindow, tc.cfg.MaxWindow)
}

func (tc *ThrottleController) loop() {
	defer tc.wg.Done()
	ticker := time.NewTicker(tc.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tc.adjust()
		case <-tc.stopCh:
			return
		}
	}
}

// Stop shuts down the monitor.
func (tc *ThrottleController) Stop() {
	close(tc.stopCh)
	tc.wg.Wait()
}

// adjust reads current CPU usage and adjusts the aggregation window.
func (tc *ThrottleController) adjust() {
	cpu := readCPUUsage()
	if cpu < 0 {
		return
	}

	var newWindow time.Duration

	switch {
	case cpu <= tc.cfg.CPULow:
		// Low CPU — use minimum window (most responsive)
		newWindow = tc.cfg.MinWindow
	case cpu >= tc.cfg.CPUHigh:
		// High CPU — use maximum window (most folding)
		newWindow = tc.cfg.MaxWindow
	default:
		// Scale linearly between min and max
		fraction := (cpu - tc.cfg.CPULow) / (tc.cfg.CPUHigh - tc.cfg.CPULow)
		windowRange := tc.cfg.MaxWindow - tc.cfg.MinWindow
		newWindow = tc.cfg.MinWindow + time.Duration(float64(windowRange)*fraction)
	}

	tc.mu.Lock()
	oldWindow := tc.currentWindow
	if newWindow != oldWindow {
		tc.currentWindow = newWindow
		if tc.agg != nil {
			tc.agg.SetFlushInterval(newWindow)
		}
		log.Printf("[throttle] CPU=%.1f%% window %v → %v", cpu, oldWindow, newWindow)
	}
	tc.mu.Unlock()
}

// CurrentWindow returns the current aggregation window.
func (tc *ThrottleController) CurrentWindow() time.Duration {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.currentWindow
}

// readCPUUsage reads the current process CPU usage from /proc/self/stat.
func readCPUUsage() float64 {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return -1
	}

	fields := strings.Fields(string(data))
	if len(fields) < 15 {
		return -1
	}

	// Extract utime (field 13) and stime (field 14) in clock ticks
	utime, _ := strconv.ParseFloat(fields[13], 64)
	stime, _ := strconv.ParseFloat(fields[14], 64)
	total := utime + stime

	// CPU percentage = total / uptime * 100 (simplified)
	// In production: use /proc/stat delta between samples
	cpu := math.Min(total*0.1, 100.0) // approximate scaling
	return cpu
}

// Stats returns throttle controller statistics.
func (tc *ThrottleController) Stats() map[string]interface{} {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return map[string]interface{}{
		"current_window": tc.currentWindow.String(),
		"min_window":     tc.cfg.MinWindow.String(),
		"max_window":     tc.cfg.MaxWindow.String(),
		"cpu_low":        tc.cfg.CPULow,
		"cpu_high":       tc.cfg.CPUHigh,
	}
}
