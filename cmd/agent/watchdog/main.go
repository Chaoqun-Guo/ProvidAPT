package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

// ─── Constants (must match kernel defense.bpf.c) ────────────

const agentFlag = 1 << 0

// ─── Main ───────────────────────────────────────────────────

func main() {
	var (
		agentPath  = flag.String("agent", "/usr/local/sbin/providaptd", "Path to proviAPT agent binary")
		configPath = flag.String("config", "/etc/providapt/providapt.toml", "Agent config path")
		interval   = flag.Duration("interval", 5*time.Second, "Health check interval")
	)
	flag.Parse()

	log.SetPrefix("[watchdog] ")
	log.Printf("ProvidAPT Watchdog starting")
	log.Printf("  agent:   %s", *agentPath)
	log.Printf("  config:  %s", *configPath)
	log.Printf("  interval: %v", *interval)

	// Remove memlock for eBPF map access
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Main monitoring loop
	for {
		select {
		case <-sigCh:
			log.Printf("watchdog shutting down")
			return

		default:
			checkAndRestart(*agentPath, *configPath)
			time.Sleep(*interval)
		}
	}
}

// ── Health check ────────────────────────────────────────────

func checkAndRestart(agentPath, configPath string) {
	running := isAgentRunning(agentPath)
	if running {
		return
	}

	log.Printf("Agent not running — restarting")

	// Start the agent
	cmd := exec.Command(agentPath, "-config", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Printf("restart failed: %v", err)
		return
	}

	pid := cmd.Process.Pid
	log.Printf("Agent restarted with PID %d", pid)

	// Wait a moment and check it's still alive
	time.Sleep(2 * time.Second)
	if cmd.Process == nil || cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		log.Printf("Agent exited immediately after restart")
	}
}

// isAgentRunning checks if the agent process is alive.
// Uses pid file check and procfs scanning.
func isAgentRunning(path string) bool {
	// Check by pid file
	pidData, err := os.ReadFile("/var/run/providaptd.pid")
	if err == nil {
		var pid int
		if _, err := fmt.Sscanf(string(pidData), "%d", &pid); err == nil && pid > 0 {
			procPath := fmt.Sprintf("/proc/%d/comm", pid)
			commData, err := os.ReadFile(procPath)
			if err == nil && string(commData) != "" {
				return true
			}
		}
	}

	// Fallback: scan procfs for our binary
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		// Must be a number
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}
		exe, err := os.Readlink("/proc/" + pid + "/exe")
		if err != nil {
			continue
		}
		if exe == path {
			return true
		}
	}
	return false
}

// ── eBPF map pinning for agent_pids map ─────────────────────

// Note: In production, the watchdog needs access to the agent_pids
// BPF map (pinned at /sys/fs/bpf/providapt/agent_pids) to register
// its own PID.  This requires the map to be pinned by the agent at
// startup and opened by the watchdog.
//
// For simplicity, the watchdog currently monitors via procfs.
// Full eBPF integration requires shared map pinning.
