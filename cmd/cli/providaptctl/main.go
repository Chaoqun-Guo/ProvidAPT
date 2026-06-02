package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	pidFile  = "/var/run/providaptd.pid"
	progName = "providaptd"
)

func main() {
	var (
		status  = flag.Bool("status", false, "Query daemon status")
		stop    = flag.Bool("stop", false, "Stop the daemon")
		restart = flag.Bool("restart", false, "Restart the daemon")
		cfgPath = flag.String("config", "/etc/providapt/providapt.toml", "Config file path")
	)
	flag.Parse()

	switch {
	case *status:
		cmdStatus(*cfgPath)
	case *stop:
		cmdStop()
	case *restart:
		cmdRestart()
	default:
		fmt.Printf(`ProvidAPTctl - control the ProvidAPT provenance monitor

Usage:
  providaptctl -status           Query daemon status
  providaptctl -stop             Stop the daemon
  providaptctl -restart          Restart the daemon
  providaptctl -config <path>    Specify config file path

Flags:
`)
		flag.PrintDefaults()
		os.Exit(1)
	}
}

func readPID() (int, error) {
	data, err := ioutil.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func isRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Sending signal 0 checks if the process exists without actually
	// delivering a signal.
	return proc.Signal(syscall.Signal(0)) == nil
}

func findDaemonPID() int {
	// Try pidfile first
	if pid, err := readPID(); err == nil && isRunning(pid) {
		return pid
	}
	// Fallback: search for providaptd process using pgrep
	cmd := exec.Command("pgrep", "-x", progName)
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0
	}
	return pid
}

func cmdStatus(cfgPath string) {
	pid := findDaemonPID()
	if pid == 0 {
		fmt.Println("ProvidAPT: stopped")
		os.Exit(1)
	}

	fmt.Printf("ProvidAPT: running (PID %d)\n", pid)

	// Check config
	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Printf("  Config: %s (exists)\n", cfgPath)
	} else {
		fmt.Printf("  Config: %s (not found)\n", cfgPath)
	}

	// Check pidfile
	if _, err := os.Stat(pidFile); err == nil {
		fmt.Printf("  PID file: %s\n", pidFile)
	}

	// Check daemon uptime via procfs
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	if data, err := ioutil.ReadFile(statPath); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 22 {
			// starttime field (field 22) is in jiffies — just show comm/state
			comm := strings.Trim(fields[1], "()")
			state := fields[2]
			fmt.Printf("  Process: %s (state %s)\n", comm, state)
		}
	}
}

func cmdStop() {
	pid := findDaemonPID()
	if pid == 0 {
		fmt.Println("ProvidAPT: not running")
		return
	}

	fmt.Printf("Stopping ProvidAPT (PID %d)...\n", pid)
	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding process: %v\n", err)
		os.Exit(1)
	}

	// Send SIGTERM for graceful shutdown
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "Error sending SIGTERM: %v\n", err)
		os.Exit(1)
	}

	// Wait for process to exit (up to 10 seconds)
	done := make(chan struct{})
	go func() {
		proc.Wait()
		close(done)
	}()

	select {
	case <-done:
		fmt.Println("ProvidAPT: stopped")
	case <-time.After(10 * time.Second):
		fmt.Println("ProvidAPT: force killing...")
		proc.Kill()
		<-done
		fmt.Println("ProvidAPT: killed")
	}

	// Clean up pidfile
	os.Remove(pidFile)
}

func cmdRestart() {
	cmdStop()
	fmt.Println("Starting ProvidAPT...")
	cmd := exec.Command(progName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting %s: %v\n", progName, err)
		os.Exit(1)
	}
	fmt.Printf("ProvidAPT: started (PID %d)\n", cmd.Process.Pid)
}

func init() {
	// Suppress unused import warning for signal on platforms without SIGTERM
	_ = signal.Notify
}
