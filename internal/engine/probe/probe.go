// Package probe detects kernel capabilities at runtime and selects
// the optimal eBPF attachment mode.  It supports automatic fallback
// from fentry/fexit to kprobe/kretprobe to tracepoint-only mode,
// ensuring ProvidAPT runs on a wide range of Linux distributions.
//
// Modes (in order of preference):
//
//   ModeFentry — fentry/fexit + fmod_ret + LSM (kernel ≥5.11, optimal)
//   ModeKprobe — kprobe/kretprobe + LSM        (kernel ≥5.5, fallback)
//   ModeTrace  — tracepoints only               (kernel ≥4.7, minimal)
//   ModeNone   — no eBPF support
package probe

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ─── Attachment mode ────────────────────────────────────────

type Mode int

const (
	ModeNone    Mode = 0
	ModeTrace   Mode = 1
	ModeKprobe  Mode = 2
	ModeFentry  Mode = 3
)

func (m Mode) String() string {
	switch m {
	case ModeFentry:
		return "fentry"
	case ModeKprobe:
		return "kprobe"
	case ModeTrace:
		return "trace"
	case ModeNone:
		return "none"
	default:
		return "unknown"
	}
}

// ─── Kernel version ─────────────────────────────────────────

// Version holds the parsed kernel version.
type Version struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion parses a Linux kernel version string.
func ParseVersion(s string) (Version, error) {
	s = strings.SplitN(s, "-", 2)[0] // strip distribution suffix
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return Version{}, fmt.Errorf("cannot parse version: %s", s)
	}
	v := Version{}
	var err error
	v.Major, err = strconv.Atoi(parts[0])
	if err != nil {
		return Version{}, fmt.Errorf("parse major version %q: %w", parts[0], err)
	}
	v.Minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return Version{}, fmt.Errorf("parse minor version %q: %w", parts[1], err)
	}
	if len(parts) > 2 {
		v.Patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return Version{}, fmt.Errorf("parse patch version %q: %w", parts[2], err)
		}
	}
	return v, nil
}

// ReleaseString returns the raw kernel release string.
func ReleaseString() string {
	release, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	if len(release) == 0 {
		return "unknown"
	}
	return strings.TrimSpace(string(release))
}

// ─── Feature detection ──────────────────────────────────────

// Result is returned by Probe().
type Result struct {
	Mode        Mode   `json:"mode"`
	ModeName    string `json:"mode_name"`
	KernelVer   string `json:"kernel_version"`
	BTFAvailable bool  `json:"btf_available"`
	BpfLSM      bool   `json:"bpf_lsm"`
	HasFentry   bool   `json:"has_fentry"`
	HasKprobe   bool   `json:"has_kprobe"`
	Reason      string `json:"reason,omitempty"`
}

// Probe detects the optimal eBPF attachment mode.
func Probe() *Result {
	r := &Result{
		KernelVer: ReleaseString(),
	}

	ver, err := ParseVersion(r.KernelVer)
	if err != nil {
		r.Mode = ModeNone
		r.Reason = fmt.Sprintf("cannot parse kernel version: %v", err)
		return r
	}

	r.BTFAvailable = checkBTF()
	r.BpfLSM = checkBpfLSM()

	// Check fentry support (kernel ≥5.11 + BTF)
	hasFentry := (ver.Major > 5 || (ver.Major == 5 && ver.Minor >= 11))
	r.HasFentry = hasFentry && r.BTFAvailable

	// Check kprobe support (kernel ≥5.5 + BTF or debugfs)
	hasKprobe := (ver.Major > 5 || (ver.Major == 5 && ver.Minor >= 5))
	if !hasKprobe {
		// Fallback: check if kprobes debugfs exists
		_, err := os.Stat("/sys/kernel/debug/kprobes")
		hasKprobe = err == nil
	}
	r.HasKprobe = hasKprobe

	// Select best mode
	switch {
	case r.HasFentry:
		r.Mode = ModeFentry
		r.Reason = "fentry/fexit + LSM (kernel ≥5.11 + BTF)"
	case hasKprobe && r.BpfLSM:
		r.Mode = ModeKprobe
		r.Reason = "kprobe + LSM (kernel ≥5.5)"
	case r.BTFAvailable:
		r.Mode = ModeTrace
		r.Reason = "tracepoint only (no BPF LSM)"
	default:
		r.Mode = ModeNone
		r.Reason = "no supported eBPF attachment mode found"
	}

	r.ModeName = r.Mode.String()
	return r
}

// ── Feature checks ──────────────────────────────────────────

func checkBTF() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

func checkBpfLSM() bool {
	// Check multiple config sources
	for _, path := range []string{
		"/proc/config.gz",
		fmt.Sprintf("/boot/config-%s", ReleaseString()),
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "CONFIG_BPF_LSM=y") {
			return true
		}
	}
	return false
}

// ── Helpers ─────────────────────────────────────────────────

// Structopt returns the eBPF program load options for the detected mode.
// In production, this controls which BPF programs to load and how.
func (r *Result) Structopt() map[string]interface{} {
	return map[string]interface{}{
		"mode":        r.Mode.String(),
		"use_lsm":     r.BpfLSM,
		"use_fentry":  r.HasFentry,
		"use_kprobe":  r.HasKprobe,
		"btf_avail":   r.BTFAvailable,
	}
}
