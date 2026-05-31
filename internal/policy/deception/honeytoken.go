package deception

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════
// Honeytoken Manager — injects phantom files via overlayfs mounts
// and monitors for access via eBPF events.
//
// Architecture:
//   ┌──────────────────────────┐
//   │  OverlayManager          │
//   │  ├── Mount() → overlayfs │── injects fake files into watched dirs
//   │  ├── Unmount()           │── removes overlay mounts
//   │  └── HandleTrigger()     │── called on eBPF trigger events
//   └──────────┬───────────────┘
//              │
//   ┌──────────▼───────────────┐
//   │  HoneypotTrigger         │── sent to Freezer + Graph integration
//   └──────────────────────────┘
// ═══════════════════════════════════════════════════════════════════

// OverlayManager manages overlayfs mounts for honeytoken injection.
// It:
//  1. Groups honeytokens by parent directory
//  2. Creates a temp upperdir with the honeytoken files
//  3. Mounts overlayfs over the target directory
//  4. Registers honeytoken paths in eBPF map for trigger detection
type OverlayManager struct {
	cfg       *Config
	mu        sync.Mutex
	mounts    []OverlayMount
	active    bool
	mapFd     int // eBPF honeytoken_map fd (-1 if not connected)
	triggerCh chan HoneypotTrigger
}

// NewOverlayManager creates a honeytoken overlay manager.
func NewOverlayManager(cfg *Config) *OverlayManager {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &OverlayManager{
		cfg:       cfg,
		mounts:    make([]OverlayMount, 0),
		mapFd:     -1,
		triggerCh: make(chan HoneypotTrigger, 256),
	}
}

// Start mounts all overlays and registers eBPF maps.
func (om *OverlayManager) Start() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if om.active {
		return fmt.Errorf("overlay manager already active")
	}

	log.Printf("[deception] starting overlay manager with %d honeytokens",
		len(om.cfg.Honeytokens))

	// Group honeytokens by parent directory.
	byDir := make(map[string][]HoneytokenDef)
	for _, ht := range om.cfg.Honeytokens {
		dir := filepath.Dir(ht.Path)
		byDir[dir] = append(byDir[dir], ht)
	}

	// Create base temp directory.
	baseDir := om.cfg.OverlayDir
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return fmt.Errorf("create overlay base dir: %w", err)
	}

	// Mount overlay for each directory.
	for targetDir, tokens := range byDir {
		mount, err := om.mountOverlay(targetDir, tokens, baseDir)
		if err != nil {
			log.Printf("[deception] overlay mount failed for %s: %v", targetDir, err)
			continue
		}
		om.mounts = append(om.mounts, *mount)
		log.Printf("[deception] overlay mounted: %s", targetDir)
	}

	// Register honeytoken paths in eBPF map (if connected).
	if om.mapFd >= 0 {
		for _, ht := range om.cfg.Honeytokens {
			if err := om.registerInEBPF(ht); err != nil {
				log.Printf("[deception] eBPF register failed for %s: %v", ht.Path, err)
			}
		}
	}

	om.active = true
	return nil
}

// Stop unmounts all overlays and cleans up.
func (om *OverlayManager) Stop() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if !om.active {
		return nil
	}

	var lastErr error
	// Unmount in reverse order.
	for i := len(om.mounts) - 1; i >= 0; i-- {
		m := om.mounts[i]
		if err := om.unmountOverlay(m); err != nil {
			log.Printf("[deception] unmount failed for %s: %v", m.TargetDir, err)
			lastErr = err
		}
	}

	// Clean up temp dirs.
	if err := os.RemoveAll(om.cfg.OverlayDir); err != nil {
		log.Printf("[deception] cleanup failed: %v", err)
	}

	om.mounts = nil
	om.active = false
	log.Println("[deception] overlay manager stopped")
	return lastErr
}

// TriggerCh returns the channel of honeytoken trigger events
// (consumed by the freezer and graph integrator).
func (om *OverlayManager) TriggerCh() <-chan HoneypotTrigger {
	return om.triggerCh
}

// HandleTrigger is called when an eBPF event signals honeytoken access.
func (om *OverlayManager) HandleTrigger(t HoneypotTrigger) {
	om.mu.Lock()
	defer om.mu.Unlock()

	log.Printf("[deception] HONEYPOT TRIGGERED: pid=%d comm=%s path=%s tripwire=%v",
		t.PID, t.Comm, t.Path, t.Tripwire)

	// Non-blocking send to trigger channel.
	select {
	case om.triggerCh <- t:
	default:
		log.Printf("[deception] trigger channel full, dropping event")
	}

	// Call external callback if configured.
	if om.cfg.OnTrigger != nil {
		om.cfg.OnTrigger(&t)
	}
}

// SetEBPFMapFd connects the manager to an eBPF honeytoken_map.
func (om *OverlayManager) SetEBPFMapFd(fd int) {
	om.mu.Lock()
	defer om.mu.Unlock()
	om.mapFd = fd
}

// ── Overlay mount operations ────────────────────────────────────

func (om *OverlayManager) mountOverlay(targetDir string, tokens []HoneytokenDef, baseDir string) (*OverlayMount, error) {
	// Validate target directory exists.
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("target dir %s does not exist", targetDir)
	}

	// Create unique upper and work dirs.
	dirHash := fnvHash(targetDir)
	upperDir := filepath.Join(baseDir, fmt.Sprintf("upper_%x", dirHash))
	workDir := filepath.Join(baseDir, fmt.Sprintf("work_%x", dirHash))

	if err := os.MkdirAll(upperDir, 0700); err != nil {
		return nil, fmt.Errorf("create upper dir: %w", err)
	}
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	// Create honeytoken files in upper dir (mirroring target structure).
	for _, ht := range tokens {
		// Relative path from target dir.
		relPath, err := filepath.Rel(targetDir, ht.Path)
		if err != nil {
			log.Printf("[deception] skip %s: %v", ht.Path, err)
			continue
		}

		fullPath := filepath.Join(upperDir, relPath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0700); err != nil {
			log.Printf("[deception] mkdir for %s: %v", fullPath, err)
			continue
		}

		// Write fake content (or a placeholder).
		content := ht.Content
		if content == "" {
			content = fmt.Sprintf("ProvidAPT honeytoken — %s (%s)", ht.Label, ht.Type)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			log.Printf("[deception] write %s: %v", fullPath, err)
			continue
		}

		log.Printf("[deception] created honeytoken: %s → %s", ht.Path, fullPath)
	}

	// Mount overlayfs.
	// mount -t overlay overlay -o lowerdir=<target>,upperdir=<upper>,workdir=<work> <target>
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", targetDir, upperDir, workDir)
	cmd := exec.Command("mount", "-t", "overlay", "overlay", "-o", opts, targetDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Clean up dirs on failure.
		os.RemoveAll(upperDir)
		os.RemoveAll(workDir)
		return nil, fmt.Errorf("mount overlay: %w (output: %s)", err, string(output))
	}

	return &OverlayMount{
		TargetDir: targetDir,
		UpperDir:  upperDir,
		WorkDir:   workDir,
		MountedAt: targetDir,
		Created:   time.Now(),
	}, nil
}

func (om *OverlayManager) unmountOverlay(m OverlayMount) error {
	cmd := exec.Command("umount", m.MountedAt)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("umount %s: %w (output: %s)", m.MountedAt, err, string(output))
	}

	// Clean up temp dirs.
	os.RemoveAll(m.UpperDir)
	os.RemoveAll(m.WorkDir)

	return nil
}

// ── eBPF map operations ─────────────────────────────────────────

func (om *OverlayManager) registerInEBPF(ht HoneytokenDef) error {
	if om.mapFd < 0 {
		return nil // no eBPF connection
	}

	pathHash := fnvHash(ht.Path)

	// In production, this writes to the honeytoken_map eBPF map:
	//   key = struct honeytoken_key { .path_hash = pathHash }
	//   val = struct honeytoken_val { .flags = HONEYPOT_ACTIVE | (tripwire ? HONEYPOT_TRIPWIRE : 0) }
	//
	// Using ebpf-go Map interface:
	//   key := uint32(pathHash)
	//   flags := uint32(HONEYPOT_ACTIVE)
	//   if ht.Tripwire { flags |= HONEYPOT_TRIPWIRE }
	//   return bpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&flags))
	//
	// For now, log the registration.
	log.Printf("[deception] eBPF register: hash=%08x path=%s tripwire=%v",
		pathHash, ht.Path, ht.Tripwire)

	return nil
}

// ── Path hash helper ─────────────────────────────────────────────

// fnvHash computes FNV-1a hash of a path string (matches eBPF kernel side).
func fnvHash(path string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(path))
	return h.Sum32()
}

// ── Query methods ───────────────────────────────────────────────

// HoneytokenByPath returns the definition for a given path, or nil.
func HoneytokenByPath(path string, tokens []HoneytokenDef) *HoneytokenDef {
	for _, ht := range tokens {
		if ht.Path == path {
			return &ht
		}
	}
	return nil
}

// HoneytokensByType returns all tokens of a given type.
func HoneytokensByType(typ HoneytokenType, tokens []HoneytokenDef) []HoneytokenDef {
	var out []HoneytokenDef
	for _, ht := range tokens {
		if ht.Type == typ {
			out = append(out, ht)
		}
	}
	return out
}

// IsHoneytokenPath checks if a path is a known honeytoken.
func IsHoneytokenPath(path string, tokens []HoneytokenDef) bool {
	return HoneytokenByPath(path, tokens) != nil
}

// Paths returns all honeytoken paths from the config.
func (om *OverlayManager) Paths() []string {
	om.mu.Lock()
	defer om.mu.Unlock()

	paths := make([]string, len(om.cfg.Honeytokens))
	for i, ht := range om.cfg.Honeytokens {
		paths[i] = ht.Path
	}
	return paths
}

// IsActive returns true if the manager is running.
func (om *OverlayManager) IsActive() bool {
	om.mu.Lock()
	defer om.mu.Unlock()
	return om.active
}

// Mounts returns the current overlay mount list.
func (om *OverlayManager) Mounts() []OverlayMount {
	om.mu.Lock()
	defer om.mu.Unlock()
	out := make([]OverlayMount, len(om.mounts))
	copy(out, om.mounts)
	return out
}

// Stats returns runtime statistics.
func (om *OverlayManager) Stats() map[string]interface{} {
	om.mu.Lock()
	defer om.mu.Unlock()
	return map[string]interface{}{
		"active":        om.active,
		"mount_count":   len(om.mounts),
		"token_count":   len(om.cfg.Honeytokens),
		"map_fd":        om.mapFd,
	}
}

// Ensure binary is used.
var _ = binary.MaxVarintLen64
