// Package memforensic implements on-demand memory forensics for
// tainted processes. It provides:
//
//  1. Trigger evaluation — check process attributes and decide when
//     to acquire memory (e.g. tainted + mprotect RW→RX).
//  2. Memory acquisition — parse /proc/<pid>/maps to locate stack
//     and executable (r-xp) segments, then read via /proc/<pid>/mem.
//  3. Fingerprint scanning — YARA integration + built-in hex pattern
//     matching for known malicious payloads (Cobalt Strike, Meterpreter).
//  4. Graph integration — attach findings to provenance node attributes.
package memforensic

import "time"

// ─────────────────────────────────────────────────────────────────
// Memory region types
// ─────────────────────────────────────────────────────────────────

// MmapPerms represents memory page permissions.
type MmapPerms string

const (
	PermRead    MmapPerms = "r"
	PermWrite   MmapPerms = "w"
	PermExec    MmapPerms = "x"
	PermReadExe MmapPerms = "r-xp"
	PermRW      MmapPerms = "rw-p"
	PermRWX     MmapPerms = "rwxp" // suspicious: W+X
	PermPriv    MmapPerms = "---p"
)

// MemoryRegion describes a single mapped memory region from /proc/pid/maps.
type MemoryRegion struct {
	Start    uint64 `json:"start"`
	End      uint64 `json:"end"`
	Perms    string `json:"perms"`
	Offset   uint64 `json:"offset"`
	Dev      string `json:"dev"`
	Inode    uint64 `json:"inode"`
	Pathname string `json:"pathname"` // [stack], [heap], /usr/bin/foo, or ""
}

// SegmentType classifies a memory region.
type SegmentType string

const (
	SegStack     SegmentType = "stack"
	SegHeap      SegmentType = "heap"
	SegExec      SegmentType = "executable"
	SegAnon      SegmentType = "anonymous"
	SegFile      SegmentType = "file-backed"
	SegVDSO      SegmentType = "vdso"
	SegVVar      SegmentType = "vvar"
	SegVSysCall  SegmentType = "vsyscall"
	SegUnknown   SegmentType = "unknown"
)

// ─────────────────────────────────────────────────────────────────
// Acquisition result
// ─────────────────────────────────────────────────────────────────

// MemDumpResult holds the raw memory dump for a process.
type MemDumpResult struct {
	PID       int             `json:"pid"`
	Comm      string          `json:"comm"`
	Regions   []MemoryRegion  `json:"regions"`
	StackData []byte          `json:"-"`
	ExecData  []byte          `json:"-"` // concatenated r-xp segments
	HeapData  []byte          `json:"-"`
	Timestamp time.Time       `json:"timestamp"`
	Error     string          `json:"error,omitempty"`
}

// HasData returns true if at least one segment was successfully read.
func (m *MemDumpResult) HasData() bool {
	return len(m.StackData) > 0 || len(m.ExecData) > 0 || len(m.HeapData) > 0
}

// SegmentCount returns the number of parsed memory regions.
func (m *MemDumpResult) SegmentCount() int {
	return len(m.Regions)
}

// ─────────────────────────────────────────────────────────────────
// Scan result types
// ─────────────────────────────────────────────────────────────────

// ScanSeverity for memory scan matches.
type ScanSeverity string

const (
	SevInfo     ScanSeverity = "info"
	SevLow      ScanSeverity = "low"
	SevMedium   ScanSeverity = "medium"
	SevHigh     ScanSeverity = "high"
	SevCritical ScanSeverity = "critical"
)

// ScanMatch is a single pattern match in dumped memory.
type ScanMatch struct {
	Rule     string            `json:"rule"`
	Severity ScanSeverity      `json:"severity"`
	Offset   uint64            `json:"offset,omitempty"`
	Segment  SegmentType       `json:"segment"`   // which segment contained the match
	Source   string            `json:"source"`    // "yara" or "hex"
	Meta     map[string]string `json:"meta,omitempty"`
}

// MemScanResult aggregates all scan findings for a process.
type MemScanResult struct {
	PID         int          `json:"pid"`
	Comm        string       `json:"comm"`
	StackHash   string       `json:"stack_hash"`   // SHA256 of stack dump
	ExecHash    string       `json:"exec_hash"`    // SHA256 of executable segments
	HeapHash    string       `json:"heap_hash"`    // SHA256 of heap dump
	Matches     []ScanMatch  `json:"matches"`
	RiskScore   float64      `json:"risk_score"`
	RiskLevel   string       `json:"risk_level"` // "low", "medium", "high", "critical"
	Timestamp   time.Time    `json:"timestamp"`
}

// MatchCount returns the number of matches by severity.
func (r *MemScanResult) MatchCount() map[ScanSeverity]int {
	counts := make(map[ScanSeverity]int)
	for _, m := range r.Matches {
		counts[m.Severity]++
	}
	return counts
}

// HasMatches returns true if any match was found.
func (r *MemScanResult) HasMatches() bool {
	return len(r.Matches) > 0
}

// ─────────────────────────────────────────────────────────────────
// Trigger types
// ─────────────────────────────────────────────────────────────────

// TriggerReason describes why a memory acquisition was triggered.
type TriggerReason string

const (
	TrigMprotectRX        TriggerReason = "MPROTECT_RW_TO_RX"
	TrigShellcodeAttr     TriggerReason = "SHELLCODE_ATTRIBUTE"
	TrigFilelessExec      TriggerReason = "FILELESS_EXECUTION"
	TrigDeepTainted       TriggerReason = "DEEP_TAINTED_PROCESS"
	TrigUnsignedMemory    TriggerReason = "UNSIGNED_MEMORY_EXEC"
	TrigManual            TriggerReason = "MANUAL_REQUEST"
	TrigSupplyChainRisk   TriggerReason = "SUPPLY_CHAIN_RISK"
)

// TriggerEvent is produced when a trigger condition is met.
type TriggerEvent struct {
	PID        int            `json:"pid"`
	Comm       string         `json:"comm"`
	Reason     TriggerReason  `json:"reason"`
	Detail     string         `json:"detail"`
	NodeAttrs  map[string]interface{} `json:"-"`
	NodeID     string         `json:"node_id"`
	HostID     string         `json:"host_id"`
	Timestamp  time.Time      `json:"timestamp"`
}

// ─────────────────────────────────────────────────────────────────
// Complete forensic result
// ─────────────────────────────────────────────────────────────────

// MemForensicResult is the complete output of the acquisition→scan pipeline.
type MemForensicResult struct {
	Trigger  TriggerReason   `json:"trigger"`
	Dump     *MemDumpResult  `json:"dump"`
	Scan     *MemScanResult  `json:"scan"`
	NodeID   string          `json:"node_id"`
	HostID   string          `json:"host_id"`
}

// NodeAttributes converts the forensic result into provenance node
// attribute key-value pairs for graph integration.
func (r *MemForensicResult) NodeAttributes() map[string]string {
	attrs := make(map[string]string)

	if r == nil {
		return attrs
	}

	attrs["mem_forensic"] = "scanned"
	attrs["mem_trigger"] = string(r.Trigger)

	if r.Scan != nil {
		attrs["mem_risk_score"] = r.Scan.RiskLevel
		attrs["mem_risk_level"] = r.Scan.RiskLevel
		attrs["mem_stack_hash"] = r.Scan.StackHash
		attrs["mem_exec_hash"] = r.Scan.ExecHash
		attrs["mem_heap_hash"] = r.Scan.HeapHash
		attrs["mem_match_count"] = fmtInt(len(r.Scan.Matches))

		if len(r.Scan.Matches) > 0 {
			top := r.Scan.Matches[0]
			attrs["mem_top_match"] = top.Rule + "/" + string(top.Severity)

			var rules []string
			for _, m := range r.Scan.Matches {
				rules = append(rules, m.Rule)
			}
			attrs["mem_matches"] = joinStrings(rules, ", ")
		}
	}

	if r.Dump != nil {
		attrs["mem_regions"] = fmtInt(r.Dump.SegmentCount())
	}

	return attrs
}

// fmtInt converts int to string without importing strconv.
func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// joinStrings joins strings with sep.
func joinStrings(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	out := elems[0]
	for _, e := range elems[1:] {
		out += sep + e
	}
	return out
}

// Ensure time is used.
var _ = time.Now
