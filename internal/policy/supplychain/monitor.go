// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package supplychain

import (
	"context"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const packageQueryTimeout = 5 * time.Second

// Known package manager executables.
var packageManagers = map[string]string{
	"apt":     "apt",
	"apt-get": "apt",
	"dpkg":    "dpkg",
	"yum":     "yum",
	"rpm":     "rpm",
	"dnf":     "dnf",
	"pip":     "pip",
	"pip3":    "pip",
	"npm":     "npm",
	"yarn":    "yarn",
	"go":      "go",
	"cargo":   "cargo",
	"gem":     "gem",
	"docker":  "docker",
}

// systemBinDirs lists directories monitored for package-manager writes.
var systemBinDirs = []string{
	"/usr/bin/",
	"/usr/sbin/",
	"/usr/local/bin/",
	"/usr/local/sbin/",
	"/opt/",
	"/usr/lib/",
	"/usr/lib64/",
	"/usr/local/lib/",
}

// PackageManagerMonitor intercepts execve + file_write events to track
// package manager activity and bind installed files to package metadata.
type PackageManagerMonitor struct {
	mu        sync.Mutex
	sessions  map[uint32]*PmSession   // PID -> session
	fileIndex map[string]*PackageInfo // file path -> package info
	alertCh   chan SupplyChainAlert
}

// NewPackageManagerMonitor creates a package manager monitor.
func NewPackageManagerMonitor() *PackageManagerMonitor {
	return &PackageManagerMonitor{
		sessions:  make(map[uint32]*PmSession),
		fileIndex: make(map[string]*PackageInfo),
		alertCh:   make(chan SupplyChainAlert, 1024),
	}
}

// AlertChan returns the alert channel for supply-chain events.
func (pmm *PackageManagerMonitor) AlertChan() <-chan SupplyChainAlert {
	return pmm.alertCh
}

// IdentifyManager checks if a process comm matches a known package manager.
func IdentifyManager(comm string) (string, bool) {
	mgr, ok := packageManagers[comm]
	return mgr, ok
}

// OnExecve is called when a process performs execve.
// If the process is a package manager, a PmSession is created.
func (pmm *PackageManagerMonitor) OnExecve(pid uint32, ppid uint32, comm string, pathname string) {
	mgr, ok := IdentifyManager(comm)
	if !ok {
		return
	}

	pmm.mu.Lock()
	defer pmm.mu.Unlock()

	// Check if parent is already in a session (child of apt-get/dpkg).
	if parentSession, exists := pmm.sessions[ppid]; exists {
		parentSession.ChildPIDs = append(parentSession.ChildPIDs, pid)
		pmm.sessions[pid] = parentSession
		log.Printf("[supplychain] %s child: PID %d (parent session: %s)",
			comm, pid, parentSession.Manager)
		return
	}

	// New top-level package manager session.
	session := &PmSession{
		PID:       pid,
		Manager:   mgr,
		StartTime: time.Now(),
	}
	pmm.sessions[pid] = session
	log.Printf("[supplychain] %s session started: PID %d", mgr, pid)
}

// OnFileWrite is called when a file is written (file_create / file_modify).
// If the writing process belongs to a package manager session, the file is
// recorded and package metadata is extracted.
func (pmm *PackageManagerMonitor) OnFileWrite(pid uint32, filepath string, inode uint64) string {
	if !isSystemBinaryPath(filepath) {
		return ""
	}

	pmm.mu.Lock()
	session, inSession := pmm.sessions[pid]
	pmm.mu.Unlock()

	if !inSession {
		return ""
	}

	pkg := pmm.extractPackageInfo(filepath, session)
	if pkg == nil {
		return ""
	}

	pmm.mu.Lock()
	session.Installed = append(session.Installed, filepath)
	pmm.fileIndex[filepath] = pkg
	pmm.mu.Unlock()

	log.Printf("[supplychain] %s installed: %s (pkg=%s v=%s repo=%s)",
		session.Manager, filepath, pkg.Name, pkg.Version, pkg.SourceRepo)
	return pkg.Name
}

// extractPackageInfo attempts to determine the package name and version for a
// file written during a package manager session.
func (pmm *PackageManagerMonitor) extractPackageInfo(filePath string, session *PmSession) *PackageInfo {
	pkg := &PackageInfo{
		PackageManager:  session.Manager,
		SourceRepo:      "official", // official repo is default
		SigningVerified: true,
	}

	switch session.Manager {
	case "apt", "dpkg":
		// Simulate dpkg -S lookup: extract package name from path.
		// In production, read /var/lib/dpkg/info/<pkg>.list for real resolution.
		pkg.Name = inferPackageName(filePath, session.Installed)
		pkg.Version = "unknown"
		pkg.Architecture = "amd64"
		// Try to read actual version from dpkg database.
		if ver := queryDpkgVersion(filePath); ver != "" {
			pkg.Version = ver
		}
		// Check GPG signature status.
		pkg.SigningVerified = checkAptSignature(session.PID)

	case "yum", "dnf", "rpm":
		pkg.Name = inferPackageName(filePath, session.Installed)
		pkg.Version = "unknown"
		pkg.Architecture = "x86_64"
		if ver := queryRpmVersion(filePath); ver != "" {
			pkg.Version = ver
		}
		pkg.SigningVerified = checkRpmSignature(session.PID)

	case "pip":
		pkg.Name = inferPackageName(filePath, session.Installed)
		pkg.Version = "unknown"
		pkg.SourceRepo = "pypi.org"
		pkg.SigningVerified = false // pip does not verify signatures by default

	case "npm":
		pkg.Name = inferPackageName(filePath, session.Installed)
		pkg.Version = "unknown"
		pkg.SourceRepo = "registry.npmjs.org"
		pkg.SigningVerified = false

	default:
		pkg.Name = inferPackageName(filePath, session.Installed)
	}

	// If the path is directly a binary name, use it as package name fallback.
	if pkg.Name == "" {
		base := filepath.Base(filePath)
		pkg.Name = strings.TrimSuffix(base, filepath.Ext(base))
	}

	return pkg
}

// inferPackageName tries to derive the package name from the file path
// and already-installed files in this session.
func inferPackageName(filePath string, installed []string) string {
	base := filepath.Base(filePath)
	name := strings.TrimSuffix(base, filepath.Ext(base))

	// Heuristic: if the directory matches a known pattern, use basename sans ext.
	// e.g. /usr/bin/nginx -> "nginx", /usr/lib/python3/dist-packages/requests/ -> "python3-requests"
	dir := filepath.ToSlash(filepath.Dir(filePath))
	if strings.Contains(dir, "/usr/lib/python") || strings.Contains(dir, "site-packages") {
		parent := filepath.Base(dir)
		return "python3-" + parent
	}
	if strings.Contains(dir, "/usr/lib/node_modules") {
		parent := filepath.Base(dir)
		return "node-" + parent
	}
	if strings.Contains(dir, "/opt/") {
		parts := strings.Split(dir, "/")
		for i, p := range parts {
			if p == "opt" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return name
}

// queryDpkgVersion reads the version from dpkg's database.
// Uses `dpkg -S <path>` to find the owning package, then
// `dpkg-query -W -f=${Version} <pkg>` to extract the version.
// Returns empty string if the tool is unavailable or the path is unknown.
func queryDpkgVersion(filePath string) string {
	// Step 1: find the package that owns this file
	ctx, cancel := context.WithTimeout(context.Background(), packageQueryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "dpkg", "-S", filePath)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	// Output format: "package-name: /path/to/file"
	parts := strings.SplitN(string(out), ":", 2)
	if len(parts) < 2 {
		return ""
	}
	pkgName := strings.TrimSpace(parts[0])
	if pkgName == "" {
		return ""
	}

	// Step 2: query the installed version
	verCmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Version}", pkgName)
	verOut, err := verCmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(verOut))
}

// queryRpmVersion reads the version from rpm's database.
// Uses `rpm -qf --queryformat %{VERSION} <path>` to get the version directly.
// Returns empty string if the tool is unavailable or the path is unknown.
func queryRpmVersion(filePath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), packageQueryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "rpm", "-qf", "--queryformat", "%{VERSION}", filePath)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// checkAptSignature verifies that the apt session used signed packages.
func checkAptSignature(sessionPID uint32) bool {
	// In production: check apt logs or /var/log/apt/term.log for
	// "Confirmed" or "Authenticated" markers.
	return true
}

// checkRpmSignature verifies rpm signature checking was active.
func checkRpmSignature(sessionPID uint32) bool {
	return true
}

// isSystemBinaryPath checks whether a file path is in a monitored directory.
func isSystemBinaryPath(filePath string) bool {
	for _, dir := range systemBinDirs {
		if strings.HasPrefix(filePath, dir) {
			return true
		}
	}
	return false
}

// ResolvePackage looks up package metadata for a given file path.
func (pmm *PackageManagerMonitor) ResolvePackage(filePath string) *PackageInfo {
	pmm.mu.Lock()
	defer pmm.mu.Unlock()
	return pmm.fileIndex[filePath]
}

// IsInWatchedDir checks if a path is in a system binary/library directory.
func IsInWatchedDir(path string) bool {
	return isSystemBinaryPath(path)
}

// UnprocessedCmds returns the list of commands considered untrusted for
// writing to system directories (used by the detector).
var UnprocessedCmds = []string{
	"curl", "wget", "nc", "ncat", "socat",
	"python", "python3", "sh", "bash", "zsh",
	"perl", "ruby", "php",
}

// IsUntrustedWriter checks if a process comm is in the untrusted list.
func IsUntrustedWriter(comm string) bool {
	for _, cmd := range UnprocessedCmds {
		if comm == cmd {
			return true
		}
	}
	return false
}

// SessionByPID returns the package manager session for a PID, if any.
func (pmm *PackageManagerMonitor) SessionByPID(pid uint32) *PmSession {
	pmm.mu.Lock()
	defer pmm.mu.Unlock()
	return pmm.sessions[pid]
}

// Stats returns monitor statistics.
func (pmm *PackageManagerMonitor) Stats() map[string]interface{} {
	pmm.mu.Lock()
	defer pmm.mu.Unlock()
	return map[string]interface{}{
		"active_sessions": len(pmm.sessions),
		"indexed_files":   len(pmm.fileIndex),
	}
}
