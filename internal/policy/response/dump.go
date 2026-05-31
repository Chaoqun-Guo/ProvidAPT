//go:build linux

// Package response provides emergency response capabilities for
// the ProvidAPT detection engine.  When an alert's threat score
// exceeds a configurable threshold, the system can automatically:
//
//   1. Dump the process memory (via process_vm_readv)
//   2. Capture open FDs and environment variables
//   3. Lock the evidence with HMAC-SHA256 signing
//
// The signed evidence record is stored in RocksDB and bound to
// the provenance graph path for forensic admissibility.
package response

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// ═══════════════════════════════════════════════════════════════
// Process memory dump
// ═══════════════════════════════════════════════════════════════

// MemRegion describes a mapped memory region from /proc/<pid>/maps.
type MemRegion struct {
	Start    uint64
	End      uint64
	Perms    string // rwxp
	Offset   uint64
	Dev      string
	Inode    uint64
	Pathname string // anonymous, [heap], [stack], or file path
}

// ParseMaps reads /proc/<pid>/maps and returns the memory regions.
func ParseMaps(pid int) ([]MemRegion, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, fmt.Errorf("open maps: %w", err)
	}
	defer f.Close()

	var regions []MemRegion
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		// Parse address range: "7f0000000000-7f0000001000"
		addrParts := strings.SplitN(parts[0], "-", 2)
		if len(addrParts) < 2 {
			continue
		}
		start, _ := strconv.ParseUint(addrParts[0], 16, 64)
		end, _ := strconv.ParseUint(addrParts[1], 16, 64)

		region := MemRegion{
			Start:  start,
			End:    end,
			Perms:  parts[1],
			Offset: parseHex(parts[2]),
			Dev:    parts[3],
			Inode:  parseUint(parts[4]),
		}
		if len(parts) >= 6 {
			region.Pathname = strings.Join(parts[5:], " ")
		}
		regions = append(regions, region)
	}
	return regions, scanner.Err()
}

// DumpMemory dumps readable memory regions of a process using
// process_vm_readv.  Returns a map of region description → bytes.
func DumpMemory(pid int) (map[string][]byte, error) {
	regions, err := ParseMaps(pid)
	if err != nil {
		return nil, fmt.Errorf("parse maps: %w", err)
	}

	result := make(map[string][]byte)
	for _, r := range regions {
		// Only dump readable regions
		if !strings.Contains(r.Perms, "r") {
			continue
		}
		// Skip very large regions (> 64MB)
		if r.End-r.Start > 64*1024*1024 {
			continue
		}
		size := int(r.End - r.Start)
		if size <= 0 {
			continue
		}

		data := make([]byte, size)
		n, err := readProcessMemory(pid, r.Start, data)
		if err != nil || n == 0 {
			continue
		}

		label := r.Pathname
		if label == "" {
			label = fmt.Sprintf("anon_%x_%x", r.Start, r.End)
		}
		result[label] = data[:n]
	}
	return result, nil
}

// readProcessMemory uses process_vm_readv to read remote process memory.
func readProcessMemory(pid int, addr uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	localIovec := syscall.Iovec{
		Base: &buf[0],
		Len:  uint64(len(buf)),
	}
	remoteIovec := syscall.Iovec{
		Base: (*byte)(unsafe.Pointer(uintptr(addr))),
		Len:  uint64(len(buf)),
	}

	n, _, errno := syscall.Syscall6(
		syscall.SYS_PROCESS_VM_READV,
		uintptr(pid),
		uintptr(unsafe.Pointer(&localIovec)),
		1,
		uintptr(unsafe.Pointer(&remoteIovec)),
		1,
		0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("process_vm_readv: %v", errno)
	}
	return int(n), nil
}

// SaveDump writes the memory dump to disk.
func SaveDump(outDir string, pid int, regions map[string][]byte) (string, error) {
	dir := filepath.Join(outDir, fmt.Sprintf("dump_%d", pid))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	for name, data := range regions {
		// Sanitise filename
		fname := strings.ReplaceAll(name, "/", "_")
		fname = strings.ReplaceAll(fname, " ", "_")
		fname = strings.ReplaceAll(fname, "..", "_")
		if len(fname) > 200 {
			fname = fname[:200]
		}
		path := filepath.Join(dir, fname+".bin")
		if err := os.WriteFile(path, data, 0400); err != nil {
			return dir, fmt.Errorf("write %s: %w", path, err)
		}
	}
	return dir, nil
}

func parseHex(s string) uint64 {
	v, _ := strconv.ParseUint(s, 16, 64)
	return v
}

func parseUint(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// FormatDumpSize returns a human-readable size string.
func FormatDumpSize(totalBytes int) string {
	switch {
	case totalBytes > 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(totalBytes)/1024/1024)
	case totalBytes > 1024:
		return fmt.Sprintf("%.1f KB", float64(totalBytes)/1024)
	default:
		return fmt.Sprintf("%d B", totalBytes)
	}
}
