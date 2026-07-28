package collector

import (
	"fmt"
	"os"
	"os/user"
	pathpkg "path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	eventsyscall "github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

type ProcessContext struct {
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	Comm      string
	ExePath   string
	Cmdline   string
	UpdatedAt time.Time
}

type ProcessEnricher struct {
	mu       sync.Mutex
	cache    map[uint32]ProcessContext
	maxItems int
	now      func() time.Time
}

func NewProcessEnricher() *ProcessEnricher {
	return &ProcessEnricher{
		cache:    make(map[uint32]ProcessContext),
		maxItems: 8192,
		now:      time.Now,
	}
}

func (pe *ProcessEnricher) Enrich(evt *Event) {
	if evt == nil {
		return
	}
	evt.Enrich()
	pe.mu.Lock()
	defer pe.mu.Unlock()
	ctx := pe.cache[evt.PID]
	ctx.PID = evt.PID
	ctx.PPID = firstNonZero(evt.PPID, ctx.PPID)
	ctx.UID = firstNonZero(evt.UID, ctx.UID)
	ctx.GID = firstNonZero(evt.GID, ctx.GID)
	ctx.Comm = firstNonEmpty(evt.Comm, ctx.Comm)
	ctx.ExePath = firstNonEmpty(evt.ExePath, ctx.ExePath)
	ctx.Cmdline = firstNonEmpty(evt.Cmdline, ctx.Cmdline)
	ctx.UpdatedAt = pe.now()
	pe.cache[evt.PID] = ctx
	pe.applyCachedContext(evt, ctx)
	if evt.ChildPID != 0 {
		child := pe.cache[evt.ChildPID]
		child.PID = evt.ChildPID
		child.PPID = evt.PID
		child.UID = firstNonZero(evt.UID, child.UID)
		child.GID = firstNonZero(evt.GID, child.GID)
		child.UpdatedAt = pe.now()
		pe.cache[evt.ChildPID] = child
	}
	if pathUnavailable(evt.Pathname) && evt.Inode != 0 {
		if resolved := resolveOpenFDPath(evt.PID, evt.DevMajor, evt.DevMinor, evt.Inode); resolved != "" {
			evt.Pathname = resolved
		}
	}
	if inferred := inferPathFromCmdline(evt.Pathname, evt.Cmdline); inferred != "" {
		evt.Pathname = inferred
	}
	if evt.Type == eventsyscall.EventProcessExec && evt.Pathname == "" && evt.ExePath != "" {
		evt.Pathname = evt.ExePath
	}
	pe.pruneLocked()
}

func (pe *ProcessEnricher) applyCachedContext(evt *Event, ctx ProcessContext) {
	evt.Comm = firstNonEmpty(evt.Comm, ctx.Comm)
	evt.ExePath = firstNonEmpty(evt.ExePath, ctx.ExePath)
	evt.Cmdline = firstNonEmpty(evt.Cmdline, ctx.Cmdline)
	if evt.PPID == 0 {
		evt.PPID = ctx.PPID
	}
	if evt.UID == 0 && ctx.UID != 0 {
		evt.UID = ctx.UID
	}
	if evt.GID == 0 && ctx.GID != 0 {
		evt.GID = ctx.GID
	}
}

func (pe *ProcessEnricher) pruneLocked() {
	if len(pe.cache) <= pe.maxItems {
		return
	}
	cutoff := pe.now().Add(-10 * time.Minute)
	for pid, ctx := range pe.cache {
		if len(pe.cache) <= pe.maxItems {
			return
		}
		if ctx.UpdatedAt.Before(cutoff) {
			delete(pe.cache, pid)
		}
	}
}

// Enrich adds cross-referenced metadata to a raw event.
// It resolves UID to username and process executable/cmdline from /proc.
func (e *Event) Enrich() {
	if e == nil {
		return
	}
	if e.UID != 0 && !strings.Contains(e.Comm, "[") {
		if u, err := user.LookupId(strconv.Itoa(int(e.UID))); err == nil {
			e.Comm = fmt.Sprintf("%s[%s]", e.Comm, u.Username)
		}
	}
	if e.PID > 0 {
		if target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(int(e.PID)), "exe")); err == nil && target != "" {
			e.ExePath = target
		}
		if data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(e.PID)), "cmdline")); err == nil {
			cmdline := strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
			e.Cmdline = strings.TrimSpace(cmdline)
		}
	}
}

func resolveOpenFDPath(pid uint32, devMajor uint32, devMinor uint32, inode uint64) string {
	fdDir := filepath.Join("/proc", strconv.Itoa(int(pid)), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return ""
	}
	want := fmt.Sprintf("socket:[%d]", inode)
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil || target == "" {
			continue
		}
		if target == want {
			return target
		}
		info, err := os.Stat(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if sameInode(info, devMajor, devMinor, inode) {
			return target
		}
	}
	return ""
}

func sameInode(info os.FileInfo, _ uint32, _ uint32, inode uint64) bool {
	sys := info.Sys()
	if sys == nil {
		return false
	}
	value := reflect.Indirect(reflect.ValueOf(sys))
	if !value.IsValid() {
		return false
	}
	field := value.FieldByName("Ino")
	if !field.IsValid() {
		return false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint() == inode
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() >= 0 && uint64(field.Int()) == inode
	default:
		return false
	}
}

func inferPathFromCmdline(pathname string, cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" || pathpkg.IsAbs(pathname) {
		return ""
	}
	pathBase := pathpkg.Base(strings.TrimSpace(pathname))
	for _, token := range strings.Fields(cmdline) {
		candidate := strings.Trim(token, "'\"`;,()[]{}<>")
		if candidate == "" || !strings.Contains(candidate, "/") {
			continue
		}
		if strings.HasPrefix(candidate, "file://") {
			candidate = strings.TrimPrefix(candidate, "file://")
		}
		if !pathpkg.IsAbs(candidate) {
			continue
		}
		if pathUnavailable(pathname) || pathBase == "." || pathpkg.Base(candidate) == pathBase {
			return candidate
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstNonZero[T ~uint32](values ...T) T {
	var zero T
	for _, value := range values {
		if value != zero {
			return value
		}
	}
	return zero
}
