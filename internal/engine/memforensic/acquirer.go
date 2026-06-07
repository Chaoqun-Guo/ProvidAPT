// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package memforensic

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────
// Memory acquisition from /proc/<pid>/
// ─────────────────────────────────────────────────────────────────

const maxSegmentSize = 64 * 1024 * 1024 // 64 MB per segment cap

// Acquire performs a lightweight memory dump of a process by reading
// /proc/<pid>/maps and /proc/<pid>/mem.
//
// It extracts:
//   - Stack segment ([stack])
//   - Executable (r-xp) segments — the main binary + any loaded libraries
//   - Heap segment ([heap])
//
// Returns a MemDumpResult or an error if the process is inaccessible.
func Acquire(pid int) (*MemDumpResult, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid PID: %d", pid)
	}

	comm, err := readComm(pid)
	if err != nil {
		return nil, fmt.Errorf("read comm for pid %d: %w", pid, err)
	}

	regions, err := parseMaps(pid)
	if err != nil {
		return nil, fmt.Errorf("parse maps for pid %d: %w", pid, err)
	}

	memFile, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, fmt.Errorf("open /proc/%d/mem: %w", pid, err)
	}
	defer memFile.Close()

	result := &MemDumpResult{
		PID:       pid,
		Comm:      comm,
		Regions:   regions,
		Timestamp: time.Now(),
	}

	for _, reg := range regions {
		segType := classifyRegion(reg)
		data, readErr := readRegion(memFile, reg)
		if readErr != nil {
			log.Printf("[memforensic] pid %d skip %s 0x%x-0x%x: %v",
				pid, segType, reg.Start, reg.End, readErr)
			continue
		}

		switch segType {
		case SegStack:
			result.StackData = data
		case SegExec:
			result.ExecData = append(result.ExecData, data...)
		case SegHeap:
			result.HeapData = data
		}
	}

	if !result.HasData() {
		return result, fmt.Errorf("no readable memory segments for pid %d", pid)
	}

	return result, nil
}

// ── /proc/<pid>/comm ────────────────────────────────────────────

func readComm(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ── /proc/<pid>/maps parser ─────────────────────────────────────

// parseMaps reads and parses /proc/<pid>/maps.
// Format per line:
//
//	address           perms offset  dev   inode   pathname
//	555555554000-555555556000 r-xp 00000000 08:01 1234567 /usr/bin/nginx
func parseMaps(pid int) ([]MemoryRegion, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}

	var regions []MemoryRegion
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		reg, err := parseMapsLine(string(line))
		if err != nil {
			continue // skip malformed lines
		}
		regions = append(regions, reg)
	}

	if len(regions) == 0 {
		return nil, fmt.Errorf("no memory regions found in /proc/%d/maps", pid)
	}

	return regions, nil
}

func parseMapsLine(line string) (MemoryRegion, error) {
	// Address range: first field before first space
	spaces := 0
	addrEnd := 0
	for i, c := range line {
		if c == ' ' || c == '	' {
			spaces++
			if spaces == 1 {
				addrEnd = i
				break
			}
		}
	}
	if addrEnd == 0 {
		return MemoryRegion{}, fmt.Errorf("malformed maps line: %s", line)
	}

	addrPart := line[:addrEnd]
	rest := strings.Fields(line[addrEnd+1:])

	if len(rest) < 4 {
		return MemoryRegion{}, fmt.Errorf("short maps line: %s", line)
	}

	// Parse address range "555555554000-555555556000"
	parts := strings.SplitN(addrPart, "-", 2)
	if len(parts) != 2 {
		return MemoryRegion{}, fmt.Errorf("bad address range: %s", addrPart)
	}

	start, err := strconv.ParseUint(parts[0], 16, 64)
	if err != nil {
		return MemoryRegion{}, fmt.Errorf("bad start addr: %s", parts[0])
	}

	end, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return MemoryRegion{}, fmt.Errorf("bad end addr: %s", parts[1])
	}

	perms := rest[0]

	offset, _ := strconv.ParseUint(rest[1], 16, 64)

	dev := rest[2]

	inode, _ := strconv.ParseUint(rest[3], 10, 64)

	pathname := ""
	if len(rest) >= 5 {
		pathname = rest[4]
	}

	return MemoryRegion{
		Start:    start,
		End:      end,
		Perms:    perms,
		Offset:   offset,
		Dev:      dev,
		Inode:    inode,
		Pathname: pathname,
	}, nil
}

// ── Region classification ───────────────────────────────────────

func classifyRegion(r MemoryRegion) SegmentType {
	switch {
	case r.Pathname == "[stack]":
		return SegStack
	case r.Pathname == "[heap]":
		return SegHeap
	case r.Pathname == "[vdso]" || r.Pathname == "[vdso32]":
		return SegVDSO
	case r.Pathname == "[vvar]":
		return SegVVar
	case r.Pathname == "[vsyscall]":
		return SegVSysCall
	case len(r.Perms) >= 3 && strings.HasPrefix(r.Perms, "r-x"):
		return SegExec
	case r.Pathname != "":
		return SegFile
	default:
		return SegAnon
	}
}

// ── Memory reading via /proc/<pid>/mem ──────────────────────────

// readRegion reads a contiguous memory region from /proc/<pid>/mem.
func readRegion(memFile io.ReaderAt, reg MemoryRegion) ([]byte, error) {
	size := reg.End - reg.Start
	if size == 0 {
		return nil, fmt.Errorf("zero-size region")
	}
	if size > maxSegmentSize {
		return nil, fmt.Errorf("region too large: %d bytes (max %d)", size, maxSegmentSize)
	}

	buf := make([]byte, size)
	n, err := memFile.ReadAt(buf, int64(reg.Start))
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read at 0x%x: %w", reg.Start, err)
	}

	return buf[:n], nil
}

// ── Discovery helpers ───────────────────────────────────────────

// FindExecutableRegions returns only the executable (r-xp) memory regions.
func FindExecutableRegions(regions []MemoryRegion) []MemoryRegion {
	var out []MemoryRegion
	for _, r := range regions {
		if classifyRegion(r) == SegExec {
			out = append(out, r)
		}
	}
	return out
}

// FindStackRegion returns the [stack] region if found.
func FindStackRegion(regions []MemoryRegion) *MemoryRegion {
	for _, r := range regions {
		if r.Pathname == "[stack]" {
			return &r
		}
	}
	return nil
}

// FindHeapRegion returns the [heap] region if found.
func FindHeapRegion(regions []MemoryRegion) *MemoryRegion {
	for _, r := range regions {
		if r.Pathname == "[heap]" {
			return &r
		}
	}
	return nil
}

// HasWXPerms checks whether any region has writable+executable permissions
// (rwxp), which is highly suspicious and often indicates injected code.
func HasWXPerms(regions []MemoryRegion) bool {
	for _, r := range regions {
		if strings.Contains(r.Perms, "w") && strings.Contains(r.Perms, "x") {
			return true
		}
	}
	return false
}

// AnonExecRegions returns anonymous executable regions (no pathname),
// which are suspicious — often JIT spray or injected shellcode.
func AnonExecRegions(regions []MemoryRegion) []MemoryRegion {
	var out []MemoryRegion
	for _, r := range regions {
		if r.Pathname == "" && strings.HasPrefix(r.Perms, "r-x") {
			out = append(out, r)
		}
	}
	return out
}

// TotalExecSize returns the total size of executable regions.
func TotalExecSize(regions []MemoryRegion) uint64 {
	var total uint64
	for _, r := range regions {
		if strings.HasPrefix(r.Perms, "r-x") {
			total += r.End - r.Start
		}
	}
	return total
}
