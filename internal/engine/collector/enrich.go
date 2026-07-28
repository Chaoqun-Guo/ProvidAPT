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
	PID           uint32
	PPID          uint32
	UID           uint32
	GID           uint32
	Comm          string
	ExePath       string
	Cmdline       string
	CmdlineSource string
	Cwd           string
	UpdatedAt     time.Time
}

type ProcessEnricher struct {
	mu        sync.Mutex
	cache     map[uint32]ProcessContext
	pathCache map[string]string
	maxItems  int
	now       func() time.Time
}

func NewProcessEnricher() *ProcessEnricher {
	return &ProcessEnricher{
		cache:     make(map[uint32]ProcessContext),
		pathCache: make(map[string]string),
		maxItems:  8192,
		now:       time.Now,
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
	ctx.CmdlineSource = firstNonEmpty(evt.CmdlineSource, ctx.CmdlineSource)
	ctx.Cwd = firstNonEmpty(evt.Cwd, ctx.Cwd)
	ctx.UpdatedAt = pe.now()
	pe.cache[evt.PID] = ctx
	pe.applyCachedContext(evt, ctx)
	if evt.ChildPID != 0 {
		child := pe.cache[evt.ChildPID]
		child.PID = evt.ChildPID
		child.PPID = evt.PID
		child.UID = firstNonZero(evt.UID, child.UID)
		child.GID = firstNonZero(evt.GID, child.GID)
		child.Cwd = firstNonEmpty(evt.Cwd, child.Cwd)
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
	if inferred := inferPathFromCwd(evt.Pathname, evt.Cwd); inferred != "" {
		evt.Pathname = inferred
	}
	if inferred := pe.resolveCachedInodePath(evt.Pathname, evt.DevMajor, evt.DevMinor, evt.Inode); inferred != "" {
		evt.Pathname = inferred
	}
	if evt.Type == eventsyscall.EventProcessExec && evt.Pathname == "" && evt.ExePath != "" {
		evt.Pathname = evt.ExePath
	}
	if evt.Type == eventsyscall.EventProcessExec && evt.Cmdline == "" && evt.Pathname != "" && !pathUnavailable(evt.Pathname) {
		evt.Cmdline = evt.Pathname
		evt.CmdlineSource = "exec_path"
	}
	pe.pruneLocked()
}

func (pe *ProcessEnricher) resolveCachedInodePath(pathname string, devMajor uint32, devMinor uint32, inode uint64) string {
	if inode == 0 || pathpkg.IsAbs(pathname) || strings.HasPrefix(pathname, "inode://") || !isWorthInodePathScan(pathname) {
		return ""
	}
	key := fmt.Sprintf("%d:%d/%d/%s", devMajor, devMinor, inode, pathpkg.Base(pathname))
	if cached := pe.pathCache[key]; cached != "" {
		return cached
	}
	resolved := resolveInodePath(pathname, devMajor, devMinor, inode)
	if resolved != "" {
		if len(pe.pathCache) > pe.maxItems {
			clear(pe.pathCache)
		}
		pe.pathCache[key] = resolved
	}
	return resolved
}

func (pe *ProcessEnricher) applyCachedContext(evt *Event, ctx ProcessContext) {
	evt.Comm = firstNonEmpty(evt.Comm, ctx.Comm)
	evt.ExePath = firstNonEmpty(evt.ExePath, ctx.ExePath)
	if strings.TrimSpace(evt.Cmdline) == "" && strings.TrimSpace(ctx.Cmdline) != "" {
		evt.Cmdline = ctx.Cmdline
		evt.CmdlineSource = firstNonEmpty(ctx.CmdlineSource, "cache")
	} else {
		evt.CmdlineSource = firstNonEmpty(evt.CmdlineSource, ctx.CmdlineSource)
	}
	evt.Cwd = firstNonEmpty(evt.Cwd, ctx.Cwd)
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
			if e.Cmdline != "" {
				e.CmdlineSource = "procfs"
			}
		}
		if target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(int(e.PID)), "cwd")); err == nil && target != "" {
			e.Cwd = target
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

func inferPathFromCwd(pathname string, cwd string) string {
	pathname = strings.TrimSpace(pathname)
	cwd = strings.TrimSpace(cwd)
	if cwd == "" || pathname == "" || pathpkg.IsAbs(pathname) || strings.HasPrefix(pathname, "inode://") {
		return ""
	}
	if isPseudoPathname(pathname) || strings.Contains(pathname, "/") {
		return ""
	}
	if !pathpkg.IsAbs(cwd) {
		return ""
	}
	return pathpkg.Clean(pathpkg.Join(cwd, pathname))
}

func resolveInodePath(pathname string, devMajor uint32, devMinor uint32, inode uint64) string {
	base := pathpkg.Base(strings.TrimSpace(pathname))
	if base == "" || base == "." || isPseudoPathname(base) {
		return ""
	}
	roots := inodeSearchRoots(base)
	visited := 0
	const maxVisited = 20000
	for _, root := range roots {
		root = filepath.Clean(root)
		if root == "." || root == string(filepath.Separator) {
			continue
		}
		var found string
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil || found != "" {
				return nil
			}
			visited++
			if visited > maxVisited {
				return filepath.SkipAll
			}
			if entry.IsDir() {
				if shouldSkipInodeSearchDir(path, entry.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Name() != base {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return nil
			}
			if sameInode(info, devMajor, devMinor, inode) {
				found = filepath.ToSlash(path)
				return filepath.SkipAll
			}
			return nil
		})
		if found != "" {
			return found
		}
	}
	return ""
}

func inodeSearchRoots(base string) []string {
	switch base {
	case "passwd", "shadow", "group", "gshadow", "sudoers", "crontab":
		return []string{"/etc"}
	default:
		return []string{"/tmp", "/var/tmp", "/home", "/root", "/etc"}
	}
}

func shouldSkipInodeSearchDir(pathname string, name string) bool {
	if name == "" {
		return false
	}
	switch name {
	case ".git", "node_modules", "vendor", "__pycache__", ".cache", ".conda", ".local", "go", "pkg":
		return true
	default:
		return strings.HasPrefix(pathname, "/home/") && (name == "Downloads" || name == "Videos" || name == "Pictures")
	}
}

func isWorthInodePathScan(pathname string) bool {
	base := strings.TrimSpace(pathpkg.Base(pathname))
	if base == "" || base == "." || isPseudoPathname(base) {
		return false
	}
	switch base {
	case "passwd", "shadow", "group", "gshadow", "sudoers", "crontab":
		return true
	}
	lower := strings.ToLower(base)
	if strings.HasPrefix(lower, "lc_") ||
		strings.HasPrefix(lower, "lib") ||
		strings.Contains(lower, "locale") ||
		strings.Contains(lower, "gconv") {
		return false
	}
	if strings.Contains(lower, "payload") ||
		strings.Contains(lower, "providapt") ||
		strings.Contains(lower, "evil") ||
		strings.Contains(lower, "backdoor") ||
		strings.Contains(lower, "attack") {
		return true
	}
	for _, suffix := range []string{".sh", ".py", ".pl", ".rb", ".bin", ".txt", ".conf", ".service", ".key", ".pem", ".cron"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func isPseudoPathname(pathname string) bool {
	switch strings.TrimSpace(pathname) {
	case ".", "..", "null", "zero", "random", "urandom", "stdin", "stdout", "stderr",
		"cmdline", "environ", "status", "maps", "mem", "fd", "socket", "pipe", "anon_inode":
		return true
	default:
		return strings.HasPrefix(pathname, "[") || strings.HasSuffix(pathname, "]")
	}
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
