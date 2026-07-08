// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// /proc/kallsyms parser — manual symbol resolution for non-
// standard kernels where CO-RE / BTF is unavailable.
//
// When the CO-RE relocation fails (e.g. custom kernel without BTF),
// we fall back to reading /proc/kallsyms to resolve function
// addresses for kprobe attachment.
// ═══════════════════════════════════════════════════════════════

// Kallsyms holds the parsed symbol table.
type Kallsyms struct {
	entries map[string]uint64 // symbol name → address
	byAddr  map[uint64]string // address → symbol name
}

// SymbolType indicates the symbol type (T=t, D=data, etc.)
type SymbolType string

const (
	SymbolText  SymbolType = "t" // .text (local)
	SymbolTextG SymbolType = "T" // .text (global)
	SymbolData  SymbolType = "d" // .data
	SymbolDataG SymbolType = "D" // .data (global)
)

// ReadKallsyms parses /proc/kallsyms into a lookup table.
// Requires root privileges (or kptr_restrict = 0).
func ReadKallsyms() (*Kallsyms, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("open kallsyms: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	ks := &Kallsyms{
		entries: make(map[string]uint64),
		byAddr:  make(map[uint64]string),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil || addr == 0 {
			// Address might be 0 for unexported symbols
			continue
		}

		// Store by symbol name
		symName := parts[2]
		ks.entries[symName] = addr
		ks.byAddr[addr] = symName
	}

	return ks, scanner.Err()
}

// Lookup returns the address of a kernel symbol.
func (ks *Kallsyms) Lookup(symbol string) (uint64, bool) {
	addr, ok := ks.entries[symbol]
	return addr, ok
}

// LookupPrefix returns all symbols with the given prefix.
func (ks *Kallsyms) LookupPrefix(prefix string) map[string]uint64 {
	result := make(map[string]uint64)
	for name, addr := range ks.entries {
		if strings.HasPrefix(name, prefix) {
			result[name] = addr
		}
	}
	return result
}

// ResolveSecurityHooks returns addresses of all security_* hooks.
// Used when CO-RE is unavailable and we need to attach kprobes
// to LSM functions by address.
func (ks *Kallsyms) ResolveSecurityHooks() map[string]uint64 {
	return ks.LookupPrefix("security_")
}

// BPFSymbols returns addresses of BPF-related symbols for kprobe
// attachment.
func (ks *Kallsyms) BPFSymbols() map[string]uint64 {
	wanted := []string{
		"security_file_open",
		"security_file_permission",
		"security_bprm_check",
		"security_task_alloc",
		"security_task_free",
		"security_socket_connect",
		"do_sys_open",
		"do_sys_openat2",
		"__x64_sys_execve",
		"__x64_sys_clone",
		"__x64_sys_fork",
		"memfd_create",
		"do_mprotect",
		"do_mmap",
	}
	result := make(map[string]uint64)
	for _, sym := range wanted {
		if addr, ok := ks.entries[sym]; ok {
			result[sym] = addr
		}
	}
	return result
}

// Count returns the number of parsed symbols.
func (ks *Kallsyms) Count() int {
	return len(ks.entries)
}

// Stats returns a summary of resolved symbols.
func (ks *Kallsyms) Stats() map[string]int {
	secHooks := len(ks.LookupPrefix("security_"))
	bpfSyms := len(ks.LookupPrefix("bpf_"))
	return map[string]int{
		"total":          ks.Count(),
		"security_hooks": secHooks,
		"bpf_symbols":    bpfSyms,
		"tracepoints":    len(ks.LookupPrefix("__tracepoint_")),
	}
}

// AttachmentPoints builds a list of kprobe attachment points for
// the current kernel, using resolved addresses from kallsyms.
func (ks *Kallsyms) AttachmentPoints() []AttachmentPoint {
	syms := ks.BPFSymbols()
	var points []AttachmentPoint
	for sym, addr := range syms {
		points = append(points, AttachmentPoint{
			Symbol:  sym,
			Address: addr,
			Mode:    ModeKprobe,
		})
	}
	return points
}

// AttachmentPoint describes where to attach a kprobe when fentry
// is unavailable.
type AttachmentPoint struct {
	Symbol  string `json:"symbol"`
	Address uint64 `json:"address"`
	Mode    Mode   `json:"mode"`
}
