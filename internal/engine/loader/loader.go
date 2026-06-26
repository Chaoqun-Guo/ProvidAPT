// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loader

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/control"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// AttachmentMode describes how eBPF programs are attached.
type AttachmentMode int

const (
	ModeLSM            AttachmentMode = iota // LSM hooks (default, requires CONFIG_BPF_LSM)
	ModeKprobeFallback                       // Kprobe attachment (CO-RE load succeeded, LSM unavailable)
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
	hooks      HookConfig
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
	return NewWithAudit(cfg, nil)
}

// NewWithAudit loads eBPF objects, attaches hooks, and returns a Loader.
// When an audit store is provided, attachment mode transitions and fallback
// behavior are recorded during initialization.
func NewWithAudit(cfg *config.Config, auditStore *audit.Store) (*Loader, error) {
	hooks, err := ParseHookConfig(cfg.Kernel.Hooks)
	if err != nil {
		return nil, err
	}
	attachmentMode := strings.ToLower(strings.TrimSpace(cfg.Kernel.AttachmentMode))
	if attachmentMode == "" {
		attachmentMode = "auto"
	}

	l := &Loader{
		hooks:      hooks,
		auditStore: auditStore,
	}

	reloadObjects := func(mode string) error {
		var objs bpfObjects
		if err := loadBpfForMode(&objs, nil, mode); err != nil {
			return fmt.Errorf("load eBPF objects: %w", err)
		}
		if l.objs != nil {
			l.objs.Close()
		}
		l.objs = &objs
		l.Ctrl = control.New(objs.PidWhitelist, objs.TaintMap, objs.SampleCounters, objs.HotPaths)
		return nil
	}

	attachKprobes := func(reason string) (*Loader, error) {
		if reason != "" {
			log.Printf("[loader] %s; trying kprobe fallback", reason)
		}
		if l.auditStore != nil {
			l.auditStore.Log(audit.Entry{
				Category: audit.CatSystem,
				Severity: "WARNING",
				Message:  reason,
				Source:   "loader",
			})
		}

		kprobeLinks, kpErr := l.attachKprobeFallback()
		if kpErr != nil {
			l.Close()
			return nil, fmt.Errorf("kprobe fallback failed: %w", kpErr)
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
		return l, nil
	}

	switch attachmentMode {
	case "kprobe":
		if err := reloadObjects("kprobe"); err != nil {
			return nil, err
		}
		if _, err := attachKprobes("kernel attachment mode forced to kprobe"); err != nil {
			return nil, err
		}
	case "lsm":
		if err := reloadObjects("lsm"); err != nil {
			return nil, err
		}
		lsmLinks, lsmErr := l.attachLSMHooks()
		if lsmErr != nil {
			l.Close()
			return nil, fmt.Errorf("attach LSM hooks: %w", lsmErr)
		}
		l.links = append(l.links, lsmLinks...)
		l.Mode = ModeLSM
	default:
		if err := reloadObjects("lsm"); err != nil {
			return nil, err
		}
		// Try LSM hooks first
		lsmLinks, lsmErr := l.attachLSMHooks()
		if lsmErr != nil {
			l.Close()
			l.links = nil
			l.Mode = ModeLSM
			if err := reloadObjects("kprobe"); err != nil {
				return nil, fmt.Errorf("LSM attach failed and kprobe object load failed: %w (LSM error: %v)", err, lsmErr)
			}
			if _, err := attachKprobes(fmt.Sprintf("LSM attach failed, falling back to kprobe: %v", lsmErr)); err != nil {
				return nil, fmt.Errorf("kprobe fallback also failed: %w (LSM error: %v)", err, lsmErr)
			}
		} else {
			l.links = append(l.links, lsmLinks...)
			l.Mode = ModeLSM
		}
	}

	// Attach tracepoints (may be skipped in extreme fallback, but try)
	tpLinks, tpErr := l.attachTracepoints()
	if tpErr != nil {
		log.Printf("[loader] tracepoint attach failed: %v (non-fatal)", tpErr)
	} else {
		l.links = append(l.links, tpLinks...)
	}

	// Open ring buffer reader
	rb, err := ringbuf.NewReader(l.objs.Rb)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	l.RB = rb

	return l, nil
}

// attachKprobeFallback attaches eBPF programs via kprobes instead of
// LSM hooks, using kernel symbols for fallback attachment.
func (l *Loader) attachKprobeFallback() ([]link.Link, error) {
	var links []link.Link
	for _, spec := range l.kprobeSpecs() {
		if spec.program == nil {
			continue
		}

		attached := false
		for _, symbol := range spec.symbols {
			lnk, err := link.Kprobe(symbol, spec.program, nil)
			if err != nil {
				log.Printf("[loader] kprobe fallback: %s attach failed: %v (skipping)", symbol, err)
				continue
			}
			links = append(links, lnk)
			attached = true
			break
		}

		if !attached {
			log.Printf("[loader] kprobe fallback: no symbol attached for hook %s", spec.hook)
		}
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

// attachLSMHooks attaches all configured LSM eBPF programs.
func (l *Loader) attachLSMHooks() ([]link.Link, error) {
	var links []link.Link

	for _, spec := range l.lsmSpecs() {
		if spec.program == nil {
			continue
		}
		lnk, err := link.AttachLSM(link.LSMOptions{
			Program: spec.program,
		})
		if err != nil {
			return nil, fmt.Errorf("attach LSM %s: %w", spec.hook, err)
		}
		links = append(links, lnk)
	}

	if len(links) == 0 {
		return nil, fmt.Errorf("no LSM hooks enabled")
	}

	return links, nil
}

// attachTracepoints attaches tracepoint programs.
func (l *Loader) attachTracepoints() ([]link.Link, error) {
	return nil, nil
}

// PinMaps pins eBPF maps to bpffs so they remain accessible after
// the process drops privileges. Must be called before DropPrivileges.
func (l *Loader) PinMaps(pinPath string) error {
	l.pinDir = pinPath
	maps := map[string]*ebpf.Map{
		"pid_whitelist":   l.objs.PidWhitelist,
		"taint_map":       l.objs.TaintMap,
		"sample_counters": l.objs.SampleCounters,
		"hot_paths":       l.objs.HotPaths,
		"ring_buffer":     l.objs.Rb,
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

type lsmAttachSpec struct {
	hook    HookID
	program *ebpf.Program
}

type kprobeAttachSpec struct {
	hook    HookID
	program *ebpf.Program
	symbols []string
}

func (l *Loader) activeHooks() []HookID {
	if len(l.hooks.EnabledHooks) == 0 {
		return DefaultHooks().EnabledHooks
	}
	return l.hooks.EnabledHooks
}

func (l *Loader) lsmSpecs() []lsmAttachSpec {
	programs := map[HookID]*ebpf.Program{
		HookTaskAlloc:      l.objs.ProbeTaskAlloc,
		HookTaskFree:       l.objs.ProbeTaskFree,
		HookFileOpen:       l.objs.ProbeFileOpen,
		HookBprmCheck:      l.objs.ProbeBprmCheck,
		HookSocketConnect:  l.objs.ProbeSocketConnect,
		HookFilePermission: l.objs.ProbeFilePermission,
	}

	specs := make([]lsmAttachSpec, 0, len(l.activeHooks()))
	for _, hook := range l.activeHooks() {
		specs = append(specs, lsmAttachSpec{
			hook:    hook,
			program: programs[hook],
		})
	}
	return specs
}

func (l *Loader) kprobeSpecs() []kprobeAttachSpec {
	programs := map[HookID]*ebpf.Program{
		HookTaskAlloc:      l.objs.ProbeTaskAlloc,
		HookTaskFree:       l.objs.ProbeTaskFree,
		HookFileOpen:       l.objs.ProbeFileOpen,
		HookBprmCheck:      l.objs.ProbeBprmCheck,
		HookSocketConnect:  l.objs.ProbeSocketConnect,
		HookFilePermission: l.objs.ProbeFilePermission,
	}

	symbols := map[HookID][]string{
		HookFileOpen:       {"security_file_open"},
		HookBprmCheck:      {"security_bprm_check"},
		HookTaskAlloc:      {"copy_process"},
		HookTaskFree:       {"do_exit"},
		HookSocketConnect:  {"__sys_connect"},
		HookFilePermission: {"security_file_permission"},
	}

	specs := make([]kprobeAttachSpec, 0, len(l.activeHooks()))
	for _, hook := range l.activeHooks() {
		hookSymbols, ok := symbols[hook]
		if !ok {
			continue
		}
		specs = append(specs, kprobeAttachSpec{
			hook:    hook,
			program: programs[hook],
			symbols: hookSymbols,
		})
	}
	return specs
}
