//go:build linux

// Package sanity provides pre-flight environment checks for ProvidAPT daemon startup.
// It validates kernel version, eBPF capabilities, filesystem state, and system configuration,
// providing actionable fix suggestions for each failing check.
package sanity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

// Status represents a check result status.
type Status int

const (
	PASS Status = iota
	FAIL
	WARN
)

func (s Status) String() string {
	switch s {
	case PASS:
		return "PASS"
	case FAIL:
		return "FAIL"
	case WARN:
		return "WARN"
	default:
		return "UNKNOWN"
	}
}

// CheckResult holds the outcome of a single sanity check.
type CheckResult struct {
	Name          string `json:"name"`
	Status        Status `json:"status"`
	Message       string `json:"message"`
	FixSuggestion string `json:"fix_suggestion,omitempty"`
}

// Report aggregates all check results.
type Report struct {
	Results   []CheckResult `json:"results"`
	Passed    int           `json:"passed"`
	Failed    int           `json:"failed"`
	Warnings  int           `json:"warnings"`
	Timestamp time.Time     `json:"timestamp"`
}

// HasFailures returns true if any check failed.
func (r *Report) HasFailures() bool {
	return r.Failed > 0
}

// Summary returns a one-line summary string.
func (r *Report) Summary() string {
	return fmt.Sprintf("%d passed, %d failed, %d warnings", r.Passed, r.Failed, r.Warnings)
}

// RunChecks executes all environment checks. skipList is a list of check names to skip.
func RunChecks(cfg *config.Config, skipList []string) *Report {
	skip := make(map[string]bool)
	for _, name := range skipList {
		skip[name] = true
	}

	report := &Report{Timestamp: time.Now()}

	checks := []struct {
		name string
		fn   func() CheckResult
	}{
		{"kernel_version", checkKernelVersion},
		{"btf_available", checkBTF},
		{"bpf_lsm", checkBPFLSM},
		{"bpffs_mounted", checkBPFFS},
		{"capabilities", checkCapabilities},
		{"data_dir_writable", func() CheckResult { return checkDataDir(cfg) }},
		{"pidfile_stale", checkPIDFile},
		{"no_conflicting_ebpf", checkConflictingProgs},
		{"providapt_user", checkProvidaptUser},
	}

	for _, c := range checks {
		if skip[c.name] {
			report.Results = append(report.Results, CheckResult{
				Name:    c.name,
				Status:  WARN,
				Message: "skipped by user request",
			})
			report.Warnings++
			continue
		}

		result := c.fn()
		report.Results = append(report.Results, result)
		switch result.Status {
		case PASS:
			report.Passed++
		case FAIL:
			report.Failed++
		case WARN:
			report.Warnings++
		}
	}

	return report
}

// ── Individual check functions ─────────────────────────────

func checkKernelVersion() CheckResult {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return CheckResult{
			Name:    "kernel_version",
			Status:  FAIL,
			Message: "unable to determine kernel version",
			FixSuggestion: "Ensure the system is running Linux. Run 'uname -r' to check current kernel.",
		}
	}

	versionStr := strings.TrimSpace(string(out))
	parts := strings.Split(versionStr, ".")
	if len(parts) < 2 {
		return CheckResult{
			Name:    "kernel_version",
			Status:  FAIL,
			Message: fmt.Sprintf("unexpected kernel version format: %s", versionStr),
			FixSuggestion: "ProvidAPT requires Linux kernel 5.11 or later. Update your kernel and reboot.",
		}
	}

	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return CheckResult{
			Name:    "kernel_version",
			Status:  FAIL,
			Message: fmt.Sprintf("unable to parse kernel version: %s", versionStr),
			FixSuggestion: "ProvidAPT requires Linux kernel 5.11 or later.",
		}
	}

	ok := (major == 5 && minor >= 11) || major >= 6
	if !ok {
		return CheckResult{
			Name:    "kernel_version",
			Status:  FAIL,
			Message: fmt.Sprintf("kernel %d.%d detected, need 5.11+", major, minor),
			FixSuggestion: fmt.Sprintf("Upgrade Linux kernel to 5.11 or later (current: %s). On Ubuntu 20.04, run: sudo apt-get install --install-recommends linux-generic-hwe-20.04", versionStr),
		}
	}

	return CheckResult{
		Name:    "kernel_version",
		Status:  PASS,
		Message: fmt.Sprintf("kernel %s (>= 5.11)", versionStr),
	}
}

func checkBTF() CheckResult {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return CheckResult{
			Name:    "btf_available",
			Status:  FAIL,
			Message: "/sys/kernel/btf/vmlinux not found",
			FixSuggestion: "BTF (BPF Type Format) is required for CO-RE eBPF programs. " +
				"Install a kernel with CONFIG_DEBUG_INFO_BTF=y, or run: build/download_btf.sh",
		}
	}
	return CheckResult{
		Name:    "btf_available",
		Status:  PASS,
		Message: "/sys/kernel/btf/vmlinux present",
	}
}

func checkBPFLSM() CheckResult {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return CheckResult{
			Name:    "bpf_lsm",
			Status:  WARN,
			Message: "cannot read /sys/kernel/security/lsm",
			FixSuggestion: "BPF LSM may not be enabled. Add 'lsm=bpf' to kernel cmdline in /etc/default/grub GRUB_CMDLINE_LINUX, then run: sudo update-grub && sudo reboot",
		}
	}

	if !strings.Contains(string(data), "bpf") {
		return CheckResult{
			Name:    "bpf_lsm",
			Status:  FAIL,
			Message: "BPF LSM not enabled in kernel security subsystem",
			FixSuggestion: "Add 'lsm=bpf' to kernel boot parameters. Edit /etc/default/grub: GRUB_CMDLINE_LINUX=\"lsm=bpf lockdown=confidentiality\" then: sudo update-grub && sudo reboot",
		}
	}

	return CheckResult{
		Name:    "bpf_lsm",
		Status:  PASS,
		Message: "BPF LSM enabled",
	}
}

func checkBPFFS() CheckResult {
	out, err := exec.Command("mount", "-t", "bpf").Output()
	if err != nil || len(out) == 0 {
		return CheckResult{
			Name:    "bpffs_mounted",
			Status:  FAIL,
			Message: "BPF filesystem not mounted",
			FixSuggestion: "Mount the BPF filesystem: sudo mount -t bpf bpffs /sys/fs/bpf\n" +
				"To make permanent, add to /etc/fstab:\n" +
				"  bpffs /sys/fs/bpf bpf defaults 0 0",
		}
	}
	return CheckResult{
		Name:    "bpffs_mounted",
		Status:  PASS,
		Message: "BPF filesystem mounted",
	}
}

func checkCapabilities() CheckResult {
	// Check if running as root (UID 0)
	if os.Geteuid() == 0 {
		return CheckResult{
			Name:    "capabilities",
			Status:  PASS,
			Message: "running as root (all capabilities available)",
		}
	}

	// Check if process has required capabilities via /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return CheckResult{
			Name:    "capabilities",
			Status:  WARN,
			Message: "cannot determine capabilities",
			FixSuggestion: "Run as root or grant capabilities: sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep /usr/local/sbin/providaptd",
		}
	}

	// Look for CapEff (effective capability set)
	var capEff uint64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			capStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			capEff, _ = strconv.ParseUint(capStr, 16, 64)
			break
		}
	}

	// Check required capabilities (simplified check for major ones)
	// CAP_BPF = 39, CAP_PERFMON = 38, CAP_SYS_ADMIN = 21
	hasBPF := (capEff>>39)&1 == 1
	hasPerfMon := (capEff>>38)&1 == 1
	hasSysAdmin := (capEff>>21)&1 == 1

	if !hasBPF || !hasPerfMon || !hasSysAdmin {
		missing := []string{}
		if !hasBPF {
			missing = append(missing, "CAP_BPF")
		}
		if !hasPerfMon {
			missing = append(missing, "CAP_PERFMON")
		}
		if !hasSysAdmin {
			missing = append(missing, "CAP_SYS_ADMIN")
		}
		return CheckResult{
			Name:    "capabilities",
			Status:  FAIL,
			Message: fmt.Sprintf("missing capabilities: %s", strings.Join(missing, ", ")),
			FixSuggestion: fmt.Sprintf("Grant required capabilities: sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep /usr/local/sbin/providaptd\n"+
				"Or run as root. Missing: %s", strings.Join(missing, ", ")),
		}
	}

	return CheckResult{
		Name:    "capabilities",
		Status:  PASS,
		Message: "all required capabilities present",
	}
}

func checkDataDir(cfg *config.Config) CheckResult {
	dir := cfg.Output.Dir
	if dir == "" {
		dir = "/var/log/providapt"
	}

	// Check directory exists and is writable
	if err := os.MkdirAll(dir, 0755); err != nil {
		return CheckResult{
			Name:    "data_dir_writable",
			Status:  FAIL,
			Message: fmt.Sprintf("cannot create data directory %s: %v", dir, err),
			FixSuggestion: fmt.Sprintf("Create the data directory: sudo mkdir -p %s && sudo chown providapt:providapt %s", dir, dir),
		}
	}

	testFile := filepath.Join(dir, ".sanity-check")
	if err := os.WriteFile(testFile, []byte{}, 0644); err != nil {
		return CheckResult{
			Name:    "data_dir_writable",
			Status:  FAIL,
			Message: fmt.Sprintf("data directory %s not writable: %v", dir, err),
			FixSuggestion: fmt.Sprintf("Fix permissions: sudo chown -R providapt:providapt %s && sudo chmod 755 %s", dir, dir),
		}
	}
	os.Remove(testFile)

	return CheckResult{
		Name:    "data_dir_writable",
		Status:  PASS,
		Message: fmt.Sprintf("data directory %s writable", dir),
	}
}

func checkPIDFile() CheckResult {
	data, err := os.ReadFile("/var/run/providaptd.pid")
	if err != nil {
		return CheckResult{
			Name:    "pidfile_stale",
			Status:  PASS,
			Message: "no PID file present",
		}
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return CheckResult{
			Name:    "pidfile_stale",
			Status:  WARN,
			Message: fmt.Sprintf("invalid PID file content: %s", pidStr),
			FixSuggestion: "Remove the PID file: sudo rm -f /var/run/providaptd.pid",
		}
	}

	// Check if process is actually running
	proc, err := os.FindProcess(pid)
	if err != nil || proc.Signal(syscall.Signal(0)) != nil {
		return CheckResult{
			Name:    "pidfile_stale",
			Status:  WARN,
			Message: fmt.Sprintf("stale PID file: pid %d is not running", pid),
			FixSuggestion: "Remove the stale PID file: sudo rm -f /var/run/providaptd.pid",
		}
	}

	return CheckResult{
		Name:    "pidfile_stale",
		Status:  PASS,
		Message: fmt.Sprintf("daemon PID %d is running", pid),
	}
}

func checkConflictingProgs() CheckResult {
	out, err := exec.Command("bpftool", "prog", "list").Output()
	if err != nil {
		return CheckResult{
			Name:    "no_conflicting_ebpf",
			Status:  WARN,
			Message: "cannot list eBPF programs (bpftool not available)",
			FixSuggestion: "Install bpftool to verify eBPF program state: sudo apt install bpftool or equivalent for your distro.",
		}
	}

	// Check for LSM programs that might conflict
	lines := strings.Split(string(out), "\n")
	var lsmProgs []string
	for i, line := range lines {
		if strings.Contains(line, "lsm") {
			// Capture the program name from the next line
			name := ""
			if i+1 < len(lines) {
				name = strings.TrimSpace(lines[i+1])
			}
			lsmProgs = append(lsmProgs, name)
		}
	}

	if len(lsmProgs) > 2 {
		return CheckResult{
			Name:    "no_conflicting_ebpf",
			Status:  WARN,
			Message: fmt.Sprintf("found %d LSM programs loaded (may conflict): %s", len(lsmProgs), strings.Join(lsmProgs, ", ")),
			FixSuggestion: "Check for conflicting eBPF programs: sudo bpftool prog list | grep lsm\n" +
				"Remove conflicting programs from your system.",
		}
	}

	return CheckResult{
		Name:    "no_conflicting_ebpf",
		Status:  PASS,
		Message: fmt.Sprintf("%d LSM programs loaded, no conflicts expected", len(lsmProgs)),
	}
}

func checkProvidaptUser() CheckResult {
	out, err := exec.Command("id", "-u", "providapt").Output()
	if err != nil {
		return CheckResult{
			Name:    "providapt_user",
			Status:  FAIL,
			Message: "user 'providapt' does not exist",
			FixSuggestion: "Create the providapt system user: sudo useradd --system --no-create-home --uid 950 --shell /usr/sbin/nologin --comment 'ProvidAPT daemon user' providapt",
		}
	}

	uid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return CheckResult{
			Name:    "providapt_user",
			Status:  WARN,
			Message: "user 'providapt' exists but cannot determine UID",
		}
	}

	status := PASS
	msg := fmt.Sprintf("user 'providapt' exists (UID %d)", uid)
	if uid != 950 {
		status = WARN
		msg = fmt.Sprintf("user 'providapt' has UID %d, expected 950", uid)
	}

	return CheckResult{
		Name:    "providapt_user",
		Status:  status,
		Message: msg,
	}
}
