// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package diagnose collects system diagnostics into a tar.gz archive
// for troubleshooting ProvidAPT deployments.
package diagnose

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Collect gathers diagnostic data and creates a tar.gz archive at outputDir.
// Returns the path to the created archive. Individual collection failures
// are logged but do not abort the overall operation.
func Collect(outputDir string) (archivePath string, err error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	archivePath = filepath.Join(outputDir, fmt.Sprintf("providapt-diagnose-%s.tar.gz", ts))

	f, err := os.Create(archivePath)
	if err != nil {
		return "", fmt.Errorf("create archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	gw := gzip.NewWriter(f)
	defer func() { _ = gw.Close() }()

	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	// Collect all diagnostic data. Each write* function handles its own errors
	// by logging and returning empty data rather than aborting.
	writeFile(tw, "kernel.txt", collectKernelInfo())
	writeFile(tw, "probes.json", collectProbeStatus())
	writeFile(tw, "errors.log", collectErrorLogs())
	writeFile(tw, "resources.txt", collectResources())
	writeFile(tw, "config.json", readConfig())
	writeFile(tw, "metrics.txt", collectMetrics())
	writeFile(tw, "buildinfo.txt", collectBuildInfo())
	writeFile(tw, "goroutines.txt", collectGoroutines())

	return archivePath, nil
}

// writeFile adds a file to the tar archive.
func writeFile(tw *tar.Writer, name, content string) {
	if content == "" {
		content = "(no data collected)\n"
	}
	hdr := &tar.Header{
		Name:     name,
		Size:     int64(len(content)),
		Mode:     0644,
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return
	}
	_, _ = io.WriteString(tw, content)
}

// ── Data collectors ─────────────────────────────────────────

func collectKernelInfo() string {
	out := runCommand("uname", "-a")
	if bt := runCommand("cat", "/proc/version"); bt != "" {
		out += "\n/proc/version:\n" + bt
	}
	return out
}

func collectProbeStatus() string {
	info := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	// Check BTF availability
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		info["btf_available"] = true
	} else {
		info["btf_available"] = false
	}

	// Check pinned eBPF maps
	pinDir := "/sys/fs/bpf/providapt"
	if entries, err := os.ReadDir(pinDir); err == nil {
		var maps []string
		for _, e := range entries {
			maps = append(maps, e.Name())
		}
		info["pinned_maps"] = maps
		info["pinned_maps_path"] = pinDir
	} else {
		info["pinned_maps_error"] = err.Error()
	}

	// Check daemon process
	pid := findDaemonPID()
	if pid > 0 {
		info["daemon_pid"] = pid
		// Check eBPF fd info
		fdDir := fmt.Sprintf("/proc/%d/fdinfo", pid)
		if entries, err := os.ReadDir(fdDir); err == nil {
			var rbFds []string
			for _, e := range entries {
				data, _ := os.ReadFile(filepath.Join(fdDir, e.Name()))
				if strings.Contains(string(data), "ringbuf") {
					rbFds = append(rbFds, e.Name())
				}
			}
			info["ring_buffer_fds"] = rbFds
		}
	} else {
		info["daemon_running"] = false
	}

	// Check kernel config for BPF
	info["kernel_config"] = checkBPFConfig()

	data, _ := json.MarshalIndent(info, "", "  ")
	return string(data)
}

func collectErrorLogs() string {
	return runCommand("journalctl", "-u", "providapt", "-n", "100", "--no-pager", "-p", "err")
}

func collectResources() string {
	var out strings.Builder
	out.WriteString("=== memory ===\n")
	out.WriteString(runCommand("free", "-m"))
	out.WriteString("\n=== disk (data dir) ===\n")
	out.WriteString(runCommand("df", "-h", "/var/log/providapt"))
	out.WriteString("\n=== daemon process ===\n")
	out.WriteString(runCommand("ps", "aux", "--forest"))
	out.WriteString("\n=== load ===\n")
	out.WriteString(runCommand("cat", "/proc/loadavg"))
	return out.String()
}

func readConfig() string {
	data, err := os.ReadFile("/etc/providapt/providapt.toml")
	if err != nil {
		return ""
	}
	return string(data)
}

func collectMetrics() string {
	return runCommand("curl", "-s", "--max-time", "5", "http://localhost:18080/metrics")
}

func collectBuildInfo() string {
	return fmt.Sprintf("GOOS=%s\nGOARCH=%s\nGOVERSION=%s\nNumCPU=%d\n",
		runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU())
}

func collectGoroutines() string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}

// ── Helpers ────────────────────────────────────────────────

func runCommand(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func findDaemonPID() int {
	// Try PID file first
	pidData, err := os.ReadFile("/var/run/providaptd.pid")
	if err == nil {
		var pid int
		if _, e := fmt.Sscanf(strings.TrimSpace(string(pidData)), "%d", &pid); e == nil && isRunning(pid) {
			return pid
		}
	}
	// Fall back to pgrep
	out := runCommand("pgrep", "-x", "providaptd")
	if out != "" {
		var pid int
		if _, e := fmt.Sscanf(strings.TrimSpace(out), "%d", &pid); e == nil {
			return pid
		}
	}
	return 0
}

func isRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(os.Signal(nil)) == nil
}

func checkBPFConfig() map[string]interface{} {
	result := make(map[string]interface{})
	// Try to read kernel config
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "zgrep", "-E", "CONFIG_BPF=|CONFIG_BPF_LSM=|CONFIG_DEBUG_INFO_BTF=", "/proc/config.gz")
	out, err := cmd.Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				result[parts[0]] = parts[1]
			}
		}
	}
	return result
}
