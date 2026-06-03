package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/logx"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/supportbundle"
	"github.com/cilium/ebpf/rlimit"
)

// agentFlag matches the kernel defense.bpf.c constant.
const agentFlag = 1 << 0

const maxBackoff = 60 * time.Second
const initialBackoff = 1 * time.Second

func main() {
	var (
		agentPath  = flag.String("agent", "/usr/local/sbin/providaptd", "Path to proviAPT agent binary")
		configPath = flag.String("config", "/etc/providapt/providapt.toml", "Agent config path")
		interval   = flag.Duration("interval", 5*time.Second, "Health check interval")
	)
	flag.Parse()

	// Structured logging
	logx.Init("info", "json")
	logx.System().Info("watchdog starting",
		"version", version.String(),
		"agent", *agentPath,
		"config", *configPath,
		"interval", interval.String(),
	)

	// Remove memlock for eBPF map access
	if err := rlimit.RemoveMemlock(); err != nil {
		logx.System().Error("rlimit remove memlock failed", "error", err)
		os.Exit(1)
	}

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	backoff := initialBackoff

	for {
		select {
		case <-sigCh:
			logx.System().Info("watchdog shutting down")
			return

		default:
			running := isAgentRunning(*agentPath)
			if running {
				// Reset backoff on successful health check
				backoff = initialBackoff
				time.Sleep(*interval)
				continue
			}

			logx.System().Warn("agent not running — attempting restart",
				"backoff", backoff.String(),
			)

			if err := restartAgent(*agentPath, *configPath); err != nil {
				logx.System().Error("agent restart failed", "error", err)
				supportbundle.Capture(fmt.Sprintf("watchdog: restart failed after %v backoff", backoff))

				// Exponential backoff with cap
				time.Sleep(backoff)
				backoff = time.Duration(math.Min(
					float64(backoff)*2,
					float64(maxBackoff),
				))
				continue
			}

			logx.System().Info("agent restarted successfully")
			backoff = initialBackoff
			time.Sleep(*interval)
		}
	}
}

// restartAgent starts the agent and verifies it stays alive.
func restartAgent(agentPath, configPath string) error {
	cmd := exec.Command(agentPath, "-config", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	pid := cmd.Process.Pid
	logx.System().Info("agent process started", "pid", pid)

	// Wait a moment and check it's still alive
	time.Sleep(2 * time.Second)
	if cmd.Process == nil || (cmd.ProcessState != nil && cmd.ProcessState.Exited()) {
		return fmt.Errorf("agent exited immediately after restart (pid=%d)", pid)
	}

	return nil
}

// isAgentRunning checks if the agent process is alive via pid file and procfs.
func isAgentRunning(path string) bool {
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

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
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
