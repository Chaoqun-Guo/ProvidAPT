// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

// cmdDashboard starts a live terminal dashboard that monitors the
// ProvidAPT daemon and displays real-time status, event rates, graph
// stats, and recent alerts.  The display refreshes every 2 seconds.
func cmdDashboard(cfgPath string) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Print("\033[?25h\033[2J\033[H")
		os.Exit(0)
	}()

	fmt.Print("\033[?25l")              // hide cursor
	defer fmt.Print("\033[?25h\033[0m") // show cursor + reset

	outDir := resolveOutputDir(cfgPath)
	alertPath := filepath.Join(outDir, "alerts.ndjson")

	start := time.Now()
	var prevEvents, prevAlerts int
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		pid := findDaemonPID()
		events := countEventFiles(outDir)
		alerts := countAlertLines(alertPath)
		rate := float64(events-prevEvents) / 2.0
		alertRate := float64(alerts-prevAlerts) / 2.0
		prevEvents, prevAlerts = events, alerts

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		fmt.Print("\033[2J\033[H")
		renderHeader()
		renderDaemonStatus(pid, outDir)
		renderEventStats(events, rate, alerts, alertRate)
		renderResources(&m)
		renderRecentAlerts(alertPath, 5)
		renderFooter(start, pid)

		<-ticker.C
	}
}

func resolveOutputDir(cfgPath string) string {
	cfg, err := config.Load(cfgPath)
	if err == nil && cfg.Output.Dir != "" {
		return cfg.Output.Dir
	}
	return "/var/log/providapt"
}

func countEventFiles(dir string) int {
	total := int64(0)
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), "providapt-") &&
			(strings.HasSuffix(e.Name(), ".ndjson") || strings.HasSuffix(e.Name(), ".json")) {
			total += e.Size()
		}
	}
	// Approximate event count: each JSON line ~200 bytes
	return int(total / 200)
}

func countAlertLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			count++
		}
	}
	return count
}

func renderHeader() {
	const w = 68
	now := time.Now().Format("15:04:05")
	fmt.Printf("\033[36m╔%s╗\033[0m\n", strings.Repeat("═", w-2))
	fmt.Printf("\033[36m║\033[1m  ProvidAPT — Real-Time Dashboard  %*s\033[0m \033[36m║\033[0m\n",
		w-44, now)
	fmt.Printf("\033[36m╚%s╝\033[0m\n\n", strings.Repeat("═", w-2))
}

func renderDaemonStatus(pid int, outDir string) {
	fmt.Printf("\033[1m── Daemon Status ───────────────────────────────────────\033[0m\n")
	if pid > 0 {
		state := "?"
		comm := "?"
		if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 3 {
				comm = strings.Trim(fields[1], "()")
				state = stateStr(fields[2])
			}
		}
		fmt.Printf("  PID:   %d\n", pid)
		fmt.Printf("  State: %s\n", state)
		fmt.Printf("  Comm:  %s\n", comm)
	} else {
		fmt.Printf("  \033[33mDaemon not running\033[0m\n")
	}
	fmt.Printf("  Dir:   %s\n\n", outDir)
}

func stateStr(s string) string {
	switch s {
	case "R":
		return "Running"
	case "S":
		return "Sleeping"
	case "D":
		return "Disk Sleep"
	case "Z":
		return "Zombie"
	case "T":
		return "Stopped"
	default:
		return s
	}
}

func renderEventStats(events int, rate float64, alerts int, alertRate float64) {
	fmt.Printf("\033[1m── Event Processing ────────────────────────────────────\033[0m\n")
	fmt.Printf("  Events logged:  %d  (\033[32m%+.1f/s\033[0m)\n", events, rate)
	fmt.Printf("  Alerts:         %d  (\033[33m%+.1f/s\033[0m)\n", alerts, alertRate)
	fmt.Println()
}

func renderResources(m *runtime.MemStats) {
	fmt.Printf("\033[1m── System Resources ────────────────────────────────────\033[0m\n")
	fmt.Printf("  Memory:     %s / %s\n", formatBytes(int64(m.Alloc)), formatBytes(int64(m.TotalAlloc)))
	fmt.Printf("  Heap Inuse: %s\n", formatBytes(int64(m.HeapInuse)))
	fmt.Printf("  Goroutines: %d\n", runtime.NumGoroutine())
	fmt.Println()
}

func renderRecentAlerts(alertPath string, n int) {
	fmt.Printf("\033[1m── Recent Alerts ───────────────────────────────────────\033[0m\n")

	f, err := os.Open(alertPath)
	if err != nil {
		fmt.Printf("  \033[33mNo alerts file\033[0m\n\n")
		return
	}
	defer f.Close()

	var lines [][]byte
	br := bufio.NewReaderSize(f, 4096)
	for {
		line, err := br.ReadBytes('\n')
		if err == io.EOF {
			if len(line) > 0 {
				lines = append(lines, line)
			}
			break
		}
		if err != nil {
			break
		}
		lines = append(lines, line)
	}

	start := 0
	if len(lines) > n {
		start = len(lines) - n
	}

	if start >= len(lines) {
		fmt.Printf("  No alerts\n\n")
		return
	}

	for i := start; i < len(lines); i++ {
		var raw map[string]interface{}
		if err := json.Unmarshal(lines[i], &raw); err != nil {
			continue
		}
		sev, _ := raw["severity"].(string)
		headline, _ := raw["headline"].(string)
		if headline == "" {
			headline, _ = raw["pattern"].(string)
		}
		color := "0"
		switch strings.ToUpper(sev) {
		case "CRITICAL", "HIGH":
			color = "31"
		case "MEDIUM":
			color = "33"
		case "LOW", "INFO":
			color = "32"
		}
		fmt.Printf("  [\033[%sm%s\033[0m] %s\n", color, sev, shorten(headline, 50))
	}
	fmt.Println()
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func renderFooter(start time.Time, pid int) {
	fmt.Printf("\033[1m──────────────────────────────────────────────────────────\033[0m\n")
	uptime := "?"
	if pid > 0 {
		if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 22 {
				clk := 100.0
				bt, _ := strconv.ParseFloat(fields[21], 64)
				uptime = fmtDuration(time.Duration(bt/clk) * time.Second)
			}
		}
	}
	fmt.Printf("  Uptime: %s  |  Refresh: 2s  |  Ctrl+C: exit\n", uptime)
}

func fmtDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
