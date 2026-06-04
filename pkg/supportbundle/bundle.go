// Package supportbundle captures crash-site snapshots for post-mortem
// analysis on panic, SIGABRT, or watchdog-detected failures.
package supportbundle

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"
)

const bundleDir = "/var/log/providapt/support-bundle"

// HandleCrash recovers from a panic and captures a support bundle before
// re-panicking. Use as: defer supportbundle.HandleCrash()
func HandleCrash() {
	if r := recover(); r != nil {
		Capture(fmt.Sprintf("panic: %v", r))
		panic(r)
	}
}

// Capture writes a full support bundle tree under bundleDir-<timestamp>.
// reason is a short human-readable trigger description.
func Capture(reason string) error {
	ts := time.Now().UTC().Format("20060102T150405Z")
	dir := bundleDir + "-" + ts

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir bundle: %w", err)
	}

	writeFile(filepath.Join(dir, "timestamp.txt"), ts+"\n")
	writeFile(filepath.Join(dir, "reason.txt"), reason+"\n")

	writeGoroutines(filepath.Join(dir, "goroutines.txt"))
	writeBuildInfo(filepath.Join(dir, "buildinfo.txt"))
	tryWriteFile(filepath.Join(dir, "config.json"), readConfig())
	tryWriteFile(filepath.Join(dir, "daemon.log"), runCommand("journalctl", "-u", "providapt", "-n", "500", "--no-pager"))
	tryWriteFile(filepath.Join(dir, "system-info.txt"), collectSystemInfo())
	tryWriteFile(filepath.Join(dir, "metrics.txt"), runCommand("curl", "-s", "http://localhost:8080/metrics"))

	return nil
}

func writeFile(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		log.Printf("[bundle] write %s: %v", path, err)
	}
}

func tryWriteFile(path, content string) {
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			log.Printf("[bundle] write %s: %v", path, err)
		}
	}
}

func writeGoroutines(path string) {
	buf := make([]byte, 1<<20) // 1 MB
	n := runtime.Stack(buf, true)
	if err := os.WriteFile(path, buf[:n], 0644); err != nil {
		log.Printf("[bundle] write goroutines: %v", err)
	}
}

func writeBuildInfo(path string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		if err := os.WriteFile(path, []byte("(no build info)\n"), 0644); err != nil {
			log.Printf("[bundle] write buildinfo: %v", err)
		}
		return
	}
	if err := os.WriteFile(path, []byte(info.String()+"\n"), 0644); err != nil {
		log.Printf("[bundle] write buildinfo: %v", err)
	}
}

func readConfig() string {
	data, err := os.ReadFile("/etc/providapt/providapt.toml")
	if err != nil {
		return ""
	}
	return string(data)
}

func runCommand(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func collectSystemInfo() string {
	var out string
	out += "=== uname -a ===\n"
	out += runCommand("uname", "-a")
	out += "\n=== os-release ===\n"
	out += readOSRelease()
	out += "\n=== memory ===\n"
	out += runCommand("free", "-m")
	out += "\n=== disk ===\n"
	out += runCommand("df", "-h", "/var/log/providapt")
	return out
}

func readOSRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "(not found)\n"
	}
	return string(data)
}
