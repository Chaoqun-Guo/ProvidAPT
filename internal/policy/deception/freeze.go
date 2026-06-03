package deception

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
)

// ═══════════════════════════════════════════════════════════════════
// Process Freezer — uses cgroup v2 to freeze processes that trigger
// honeytokens, limiting them to 1% CPU and preserving forensic context.
//
// Architecture:
//
//	HoneypotTrigger
//	    ↓
//	Freezer.Freeze(trigger)
//	    ├── mkdir /sys/fs/cgroup/providapt-freeze/
//	    ├── echo "1 100" > cpu.max          (1% CPU quota)
//	    ├── echo $PID > cgroup.procs        (add process)
//	    ├── echo 1 > cgroup.freeze          (optional deep freeze)
//	    ├── CaptureContext(pid)             (/proc/pid/{maps,fd,env,status})
//	    └── Save FreezeRecord
//
//	Analyst → Freezer.Release(pid)
//	    ├── echo 0 > cgroup.freeze
//	    └── Remove from cgroup
// ═══════════════════════════════════════════════════════════════════

// Freezer manages process freezing via cgroup v2.
type Freezer struct {
	cfg        *Config
	mu         sync.Mutex
	records    map[int]*FreezeRecord // PID → freeze record
	auditStore *audit.Store
}

// SetAuditStore attaches an audit logging store. If set, honeypot
// trigger events are recorded to it.
func (f *Freezer) SetAuditStore(as *audit.Store) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auditStore = as
}

// NewFreezer creates a cgroup-based process freezer.
func NewFreezer(cfg *Config) *Freezer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Freezer{
		cfg:     cfg,
		records: make(map[int]*FreezeRecord),
	}
}

// Freeze applies cgroup CPU cap + optional process freeze.
//
// Steps:
//  1. Create cgroup subgroup: /sys/fs/cgroup/<CGroupName>/
//  2. Set cpu.max to "1 100" (1% of one CPU core)
//  3. Echo PID into cgroup.procs
//  4. If tripwire: echo 1 > cgroup.freeze (complete pause)
//  5. Capture /proc/PID context (maps, fd, env, status)
//  6. Store FreezeRecord
func (f *Freezer) Freeze(trigger *HoneypotTrigger) (*FreezeRecord, error) {
	if trigger == nil {
		return nil, fmt.Errorf("nil trigger")
	}

	pid := int(trigger.PID)
	log.Printf("[deception] FREEZE: pid=%d comm=%s honeytoken=%s",
		pid, trigger.Comm, trigger.Path)

	f.mu.Lock()
	defer f.mu.Unlock()

	// 1. Create cgroup path.
	cgPath := filepath.Join(f.cfg.CGroupMount, f.cfg.CGroupName)
	if err := os.MkdirAll(cgPath, 0755); err != nil {
		return nil, fmt.Errorf("create cgroup dir %s: %w", cgPath, err)
	}

	// 2. Set CPU quota: "1 100" = 1% of one core (1/100 * 1 CPU).
	//    Format: $quota $period (e.g., "10000 1000000" = 10%).
	cpuMaxPath := filepath.Join(cgPath, "cpu.max")
	cpuQuota := f.cfg.CPUQuota
	if cpuQuota <= 0 {
		cpuQuota = 1
	}
	// Convert percentage to kernel format.
	// 1% = 10000/1000000 (10ms budget per 1s period)
	cpuMaxVal := fmt.Sprintf("%d 1000000", cpuQuota*10000)
	if err := os.WriteFile(cpuMaxPath, []byte(cpuMaxVal), 0644); err != nil {
		log.Printf("[deception] cpu.max write error (may need root): %v", err)
		// Continue — partial freeze is better than none.
	}

	// 3. Add process to cgroup.
	procsPath := filepath.Join(cgPath, "cgroup.procs")
	pidStr := strconv.Itoa(pid)
	if err := os.WriteFile(procsPath, []byte(pidStr), 0644); err != nil {
		return nil, fmt.Errorf("add pid to cgroup: %w", err)
	}

	log.Printf("[deception] cgroup cpu limited: pid=%d quota=%d%% path=%s",
		pid, cpuQuota, cgPath)

	freezePath := filepath.Join(cgPath, "cgroup.freeze")

	// 4. Deep freeze for tripwire triggers.
	if trigger.Tripwire {
		if err := os.WriteFile(freezePath, []byte("1"), 0644); err != nil {
			log.Printf("[deception] cgroup.freeze error (may need newer kernel): %v", err)
		} else {
			log.Printf("[deception] process frozen: pid=%d", pid)
		}
	}

	// 5. Capture process context.
	record := &FreezeRecord{
		PID:         pid,
		Comm:        trigger.Comm,
		Trigger:     *trigger,
		State:       FreezeComplete,
		CGroupsPath: cgPath,
		FrozenAt:    time.Now(),
	}

	if f.cfg.PreserveContext {
		ctx := captureContext(pid)
		record.Context = ctx
	}

	f.records[pid] = record

	if f.auditStore != nil {
		f.auditStore.Log(audit.Entry{
			Category: audit.CatSecurity,
			Severity: "CRITICAL",
			Message:  fmt.Sprintf("Honeypot triggered by pid=%d comm=%s path=%s", pid, trigger.Comm, trigger.Path),
			Source:   "deception",
			Details: map[string]interface{}{
				"pid":      pid,
				"comm":     trigger.Comm,
				"path":     trigger.Path,
				"type":     string(trigger.TokenType),
				"trigger":  string(trigger.Trigger),
				"tripwire": trigger.Tripwire,
			},
		})
	}

	// 6. Call graph updater if configured.
	if f.cfg.GraphUpdater != nil {
		tokenType := string(trigger.TokenType)
		if tokenType == "" {
			tokenType = "unknown"
		}
		nodeID := fmt.Sprintf("p:%d", pid)
		f.cfg.GraphUpdater(nodeID, map[string]string{
			"honeypot_triggered":  "true",
			"honeypot_path":       trigger.Path,
			"honeypot_type":       tokenType,
			"honeypot_tripwire":   strconv.FormatBool(trigger.Tripwire),
			"confirmed_malicious": "true",
			"frozen_cgroup":       cgPath,
			"frozen_cpu_quota":    cpuMaxVal,
		})
	}

	return record, nil
}

// Release removes a process from cgroup control.
func (f *Freezer) Release(pid int) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	record, ok := f.records[pid]
	if !ok {
		return fmt.Errorf("no freeze record for pid %d", pid)
	}

	cgPath := record.CGroupsPath

	// 1. Unfreeze if frozen.
	freezePath := filepath.Join(cgPath, "cgroup.freeze")
	if err := os.WriteFile(freezePath, []byte("0"), 0644); err != nil {
		log.Printf("[deception] unfreeze error: %v", err)
	}

	// 2. Remove from cgroup by writing to cgroup.procs
	//    Writing the PID to the root cgroup.procs removes it.
	rootProcs := filepath.Join(f.cfg.CGroupMount, "cgroup.procs")
	if err := os.WriteFile(rootProcs, []byte(strconv.Itoa(pid)), 0644); err != nil {
		log.Printf("[deception] remove from cgroup.procs: %v", err)
	}

	now := time.Now()
	record.State = FreezeReleased
	record.ReleasedAt = &now

	log.Printf("[deception] RELEASED: pid=%d comm=%s", pid, record.Comm)
	return nil
}

// Record returns the freeze record for a PID, or nil.
func (f *Freezer) Record(pid int) *FreezeRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[pid]
}

// Records returns all freeze records.
func (f *Freezer) Records() []*FreezeRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*FreezeRecord, 0, len(f.records))
	for _, r := range f.records {
		out = append(out, r)
	}
	// Sort by PID for deterministic output.
	sort.Slice(out, func(i, j int) bool {
		return out[i].PID < out[j].PID
	})
	return out
}

// Stats returns freezer statistics.
func (f *Freezer) Stats() map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()

	var active, released int
	for _, r := range f.records {
		switch r.State {
		case FreezeComplete, FreezeCGroupSet:
			active++
		case FreezeReleased:
			released++
		}
	}

	return map[string]interface{}{
		"total_frozen":   len(f.records),
		"active_freezes": active,
		"released":       released,
	}
}

// ── Process context capture ──────────────────────────────────────

// captureContext reads /proc/<pid>/ for forensic information.
// This runs BEFORE the process is frozen so we can read its state.
func captureContext(pid int) ProcessContext {
	ctx := ProcessContext{
		PID:        pid,
		CapturedAt: time.Now(),
	}

	procDir := fmt.Sprintf("/proc/%d", pid)

	// Comm.
	if data, err := os.ReadFile(fmt.Sprintf("%s/comm", procDir)); err == nil {
		ctx.Comm = strings.TrimSpace(string(data))
	}

	// Cmdline.
	if data, err := os.ReadFile(fmt.Sprintf("%s/cmdline", procDir)); err == nil {
		// cmdline uses null bytes as separators.
		ctx.Cmdline = strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
	}

	// Status.
	if data, err := os.ReadFile(fmt.Sprintf("%s/status", procDir)); err == nil {
		ctx.Status = string(data)
	}

	// Environment variables.
	ctx.EnvVars = make(map[string]string)
	if data, err := os.ReadFile(fmt.Sprintf("%s/environ", procDir)); err == nil {
		for _, env := range strings.Split(string(data), "\x00") {
			env = strings.TrimSpace(env)
			if env == "" {
				continue
			}
			if eq := strings.IndexByte(env, '='); eq > 0 {
				key := env[:eq]
				val := env[eq+1:]
				// Truncate long values.
				if len(val) > 128 {
					val = val[:128] + "..."
				}
				ctx.EnvVars[key] = val
			}
		}
	}

	// Memory maps.
	if data, err := os.ReadFile(fmt.Sprintf("%s/maps", procDir)); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				ctx.MmapRegions = append(ctx.MmapRegions, line)
			}
		}
		// Limit to prevent bloat (first 50 entries).
		if len(ctx.MmapRegions) > 50 {
			ctx.MmapRegions = append(ctx.MmapRegions[:50], "...")
		}
	}

	// Open file descriptors.
	if fdDir, err := os.ReadDir(fmt.Sprintf("%s/fd", procDir)); err == nil {
		for _, f := range fdDir {
			if link, err := os.Readlink(fmt.Sprintf("%s/fd/%s", procDir, f.Name())); err == nil {
				ctx.OpenFDs = append(ctx.OpenFDs, fmt.Sprintf("%s → %s", f.Name(), link))
			}
		}
		// Limit.
		if len(ctx.OpenFDs) > 50 {
			ctx.OpenFDs = append(ctx.OpenFDs[:50], "...")
		}
	}

	// Seccomp mode.
	if data, err := os.ReadFile(fmt.Sprintf("%s/status", procDir)); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Seccomp:") {
				ctx.Seccomp = strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:"))
				break
			}
		}
	}

	return ctx
}

// CleanupStaleCgroups removes cgroup directories that may have been
// left behind after a crash.
func CleanupStaleCgroups(cfg *Config) error {
	cgPath := filepath.Join(cfg.CGroupMount, cfg.CGroupName)
	if _, err := os.Stat(cgPath); os.IsNotExist(err) {
		return nil
	}

	// Try to remove the cgroup directory.
	// cgroup v2 directories are removed automatically when empty
	// (all processes removed). Force removal by writing to cgroup.kill.
	killPath := filepath.Join(cgPath, "cgroup.kill")
	if _, err := os.ReadFile(killPath); err == nil {
		// Kill all processes in the cgroup.
		if err := os.WriteFile(killPath, []byte("1"), 0644); err != nil {
			log.Printf("[deception] cgroup.kill write failed: %v", err)
		}
	}

	if err := os.RemoveAll(cgPath); err != nil {
		return fmt.Errorf("remove stale cgroup %s: %w", cgPath, err)
	}
	return nil
}

