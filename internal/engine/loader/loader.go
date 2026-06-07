// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loader

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/control"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

// AttachmentMode describes how eBPF programs are attached.
type AttachmentMode int

const (
	ModeLSM    AttachmentMode = iota // LSM hooks (default, requires CONFIG_BPF_LSM)
	ModeKprobeFallback               // Kprobe attachment (CO-RE load succeeded, LSM unavailable)
)

func (m AttachmentMode) String() string {
	switch m {
	case ModeLSM:
		return "lsm"
	case ModeKprobeFallback:
		return "kprobe_fallback"
	default:
		return "unknown"
	}
}

// Loader manages eBPF programs and their attachment lifecycle.
type Loader struct {
	RB         *ringbuf.Reader
	Ctrl       *control.Controller
	Mode       AttachmentMode
	objs       *bpfObjects
	links      []link.Link
	pinDir     string
	auditStore *audit.Store
}

// SetAuditStore attaches an audit logging store. If set, fallback
// and attachment events are recorded.
func (l *Loader) SetAuditStore(as *audit.Store) {
	l.auditStore = as
}

// New loads eBPF objects, attaches hooks, and returns a Loader.
// If LSM attachment fails (e.g. no CONFIG_BPF_LSM), it automatically
// falls back to kprobe attachment when possible.
func New(cfg *config.Config) (*Loader, error) {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	l := &Loader{objs: &objs}

	// Create runtime controller for whitelist/taint management
	l.Ctrl = control.New(objs.PidWhitelist, objs.TaintMap, objs.SampleCounters, objs.HotPaths)

	// Try LSM hooks first
	lsmLinks, lsmErr := l.attachLSMHooks()
	if lsmErr != nil {
		log.Printf("[loader] LSM attach failed: %v — trying kprobe fallback", lsmErr)
		if l.auditStore != nil {
			l.auditStore.Log(audit.Entry{
				Category: audit.CatSystem,
				Severity: "WARNING",
				Message:  fmt.Sprintf("LSM attach failed, falling back to kprobe: %v", lsmErr),
				Source:   "loader",
			})
		}

		// Fallback to kprobe attachment
		kprobeLinks, kpErr := l.attachKprobeFallback()
		if kpErr != nil {
			l.Close()
			return nil, fmt.Errorf("kprobe fallback also failed: %w (LSM error: %v)", kpErr, lsmErr)
		}
		l.links = append(l.links, kprobeLinks...)
		l.Mode = ModeKprobeFallback
		log.Printf("[loader] attached %d kprobes (fallback mode)", len(kprobeLinks))

		if l.auditStore != nil {
			l.auditStore.Log(audit.Entry{
				Category: audit.CatSystem,
				Severity: "INFO",
				Message:  fmt.Sprintf("Running in kprobe fallback mode with %d probes", len(kprobeLinks)),
				Source:   "loader",
				Details: map[string]interface{}{
					"kprobe_count": len(kprobeLinks),
				},
			})
		}
	} else {
		l.links = append(l.links, lsmLinks...)
		l.Mode = ModeLSM
	}

	// Attach tracepoints (may be skipped in extreme fallback, but try)
	tpLinks, tpErr := l.attachTracepoints()
	if tpErr != nil {
		log.Printf("[loader] tracepoint attach failed: %v (non-fatal)", tpErr)
	} else {
		l.links = append(l.links, tpLinks...)
	}

	// Open ring buffer reader
	rb, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	l.RB = rb

	return l, nil
}

// attachKprobeFallback attaches eBPF programs via kprobes instead of
// LSM hooks, using kallsyms for symbol resolution.
func (l *Loader) attachKprobeFallback() ([]link.Link, error) {
	// Map of eBPF program → kernel symbols to probe.
	type kprobeAttach struct {
		prog   *ebpf.Program
		symbol string
	}

	candidates := []kprobeAttach{
		{l.objs.ProbeFileOpen, "do_sys_openat2"},
		{l.objs.ProbeFileOpen, "do_sys_open"},
		{l.objs.ProbeBprmCheck, "security_bprm_check"},
		{l.objs.ProbeTaskAlloc, "copy_process"},
		{l.objs.ProbeTaskFree, "do_exit"},
		{l.objs.ProbeSocketConnect, "__sys_connect"},
		{l.objs.ProbeFilePermission, "security_file_permission"},
	}

	// Attempt to read kallsyms for verification (non-fatal if unavailable).

	var links []link.Link
	for _, ca := range candidates {
		if ca.prog == nil {
			continue
		}
		lnk, err := link.Kprobe(ca.symbol, ca.prog, nil)
		if err != nil {
			log.Printf("[loader] kprobe fallback: %s attach failed: %v (skipping)", ca.symbol, err)
			continue
		}
		links = append(links, lnk)
	}

	if len(links) == 0 {
		return nil, fmt.Errorf("no kprobes could be attached")
	}
	return links, nil
}

// ModeName returns a human-readable attachment mode description.
func (l *Loader) ModeName() string {
	if l == nil {
		return "uninitialized"
	}
	return l.Mode.String()
}

// attachLSMHooks attaches all LSM eBPF programs.
func (l *Loader) attachLSMHooks() ([]link.Link, error) {
	var links []link.Link

	attach := []struct {
		prog *ebpf.Program
		hook string
	}{
		{l.objs.ProbeTaskAlloc, "task_alloc"},
		{l.objs.ProbeTaskFree, "task_free"},
		{l.objs.ProbeFileOpen, "file_open"},
		{l.objs.ProbeBprmCheck, "bprm_check_security"},
		{l.objs.ProbeSocketConnect, "socket_connect"},
		{l.objs.ProbeFilePermission, "file_permission"},
	}

	for _, a := range attach {
		lnk, err := link.AttachLSM(link.LSMOptions{
			Program: a.prog,
		})
		if err != nil {
			return nil, fmt.Errorf("attach LSM %s: %w", a.hook, err)
		}
		links = append(links, lnk)
	}
	return links, nil
}

// attachTracepoints attaches tracepoint programs.
func (l *Loader) attachTracepoints() ([]link.Link, error) {
	var links []link.Link

	tp, err := link.Tracepoint("sched", "sched_process_fork",
		l.objs.RawTpSchedProcessFork, nil)
	if err != nil {
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}
	links = append(links, tp)

	return links, nil
}

// PinMaps pins eBPF maps to bpffs so they remain accessible after
// the process drops privileges. Must be called before DropPrivileges.
func (l *Loader) PinMaps(pinPath string) error {
	l.pinDir = pinPath
	maps := map[string]*ebpf.Map{
		"pid_whitelist":  l.objs.PidWhitelist,
		"taint_map":      l.objs.TaintMap,
		"sample_counters": l.objs.SampleCounters,
		"hot_paths":      l.objs.HotPaths,
		"ring_buffer":    l.objs.Rb,
	}
	for name, m := range maps {
		if m != nil {
			if err := m.Pin(filepath.Join(pinPath, name)); err != nil {
				return fmt.Errorf("pin %s: %w", name, err)
			}
		}
	}
	return nil
}

// UnpinMaps removes pinned eBPF maps from bpffs.
func (l *Loader) UnpinMaps() {
	if l.pinDir == "" {
		return
	}
	for _, name := range []string{"pid_whitelist", "taint_map", "sample_counters", "hot_paths", "ring_buffer"} {
		os.Remove(filepath.Join(l.pinDir, name))
	}
}

// Close unloads all eBPF programs and releases resources.
func (l *Loader) Close() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	if l.RB != nil {
		l.RB.Close()
	}
	if l.objs != nil {
		l.objs.Close()
	}
}
