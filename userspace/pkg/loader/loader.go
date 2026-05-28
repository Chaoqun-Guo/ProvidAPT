package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/config"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/control"
)

// Loader manages eBPF programs and their attachment lifecycle.
type Loader struct {
	RB     *ringbuf.Reader
	Ctrl   *control.Controller
	objs   *bpfObjects
	links  []link.Link
}

// New loads eBPF objects, attaches hooks, and returns a Loader.
func New(cfg *config.Config) (*Loader, error) {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	l := &Loader{objs: &objs}

	// Create runtime controller for whitelist/taint management
	l.Ctrl = control.New(objs.PidWhitelist, objs.TaintMap, objs.SampleCounters)

	// Attach LSM hooks
	lsmLinks, err := l.attachLSMHooks()
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach LSM hooks: %w", err)
	}
	l.links = append(l.links, lsmLinks...)

	// Attach tracepoints
	tpLinks, err := l.attachTracepoints()
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach tracepoints: %w", err)
	}
	l.links = append(l.links, tpLinks...)

	// Open ring buffer reader
	rb, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	l.RB = rb

	return l, nil
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
