package memforensic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os/exec"
	"strings"
)

// ─────────────────────────────────────────────────────────────────
// Memory scanner — combines YARA (external binary) and built-in
// hex pattern matching for known malicious payload signatures.
// ─────────────────────────────────────────────────────────────────

// ScannerConfig configures the memory scanner.
type ScannerConfig struct {
	// YARABinary is the path to the yara executable (default "yara").
	YARABinary string

	// YARARulesPath is the path to YARA rules file or directory.
	YARARulesPath string

	// YARATimeout is the YARA scan timeout in seconds (default 30).
	YARATimeout int

	// EnableHexScanner enables built-in hex pattern matching.
	// Enabled by default for when YARA is unavailable.
	EnableHexScanner bool

	// MaxDumpSize limits the total bytes sent to YARA (default 256MB).
	MaxDumpSize int
}

// DefaultScannerConfig returns defaults.
func DefaultScannerConfig() *ScannerConfig {
	return &ScannerConfig{
		YARABinary:      "yara",
		YARATimeout:     30,
		EnableHexScanner: true,
		MaxDumpSize:     256 * 1024 * 1024,
	}
}

// MemoryScanner scans dumped memory segments for malicious patterns.
type MemoryScanner struct {
	cfg        *ScannerConfig
	hexPatterns []hexPattern
}

// NewMemoryScanner creates a memory scanner.
func NewMemoryScanner(cfg *ScannerConfig) *MemoryScanner {
	if cfg == nil {
		cfg = DefaultScannerConfig()
	}
	s := &MemoryScanner{cfg: cfg}
	if cfg.EnableHexScanner {
		s.hexPatterns = defaultHexPatterns()
	}
	return s
}

// Scan runs all enabled scanners on a dump result and returns findings.
func (ms *MemoryScanner) Scan(dump *MemDumpResult) *MemScanResult {
	result := &MemScanResult{
		PID:       dump.PID,
		Comm:      dump.Comm,
		Timestamp: dump.Timestamp,
	}

	// Compute hashes of dumped segments.
	if len(dump.StackData) > 0 {
		h := sha256.Sum256(dump.StackData)
		result.StackHash = hex.EncodeToString(h[:])
	}
	if len(dump.ExecData) > 0 {
		h := sha256.Sum256(dump.ExecData)
		result.ExecHash = hex.EncodeToString(h[:])
	}
	if len(dump.HeapData) > 0 {
		h := sha256.Sum256(dump.HeapData)
		result.HeapHash = hex.EncodeToString(h[:])
	}

	// YARA scan.
	if ms.cfg.YARARulesPath != "" {
		if yaraMatches := ms.scanWithYARA(dump); len(yaraMatches) > 0 {
			result.Matches = append(result.Matches, yaraMatches...)
		}
	}

	// Built-in hex pattern scan.
	if ms.cfg.EnableHexScanner && len(ms.hexPatterns) > 0 {
		if hexMatches := ms.scanWithHexPatterns(dump); len(hexMatches) > 0 {
			result.Matches = append(result.Matches, hexMatches...)
		}
	}

	// Calculate risk score from matches.
	result.RiskScore = calcMatchRisk(result.Matches)
	result.RiskLevel = riskLevel(result.RiskScore)

	return result
}

// ── YARA integration ────────────────────────────────────────────

func (ms *MemoryScanner) scanWithYARA(dump *MemDumpResult) []ScanMatch {
	// Write executable data to temp file for YARA scanning.
	// This is more reliable than piping via stdin.
	if len(dump.ExecData) == 0 && len(dump.StackData) == 0 {
		return nil
	}

	// We write combined executable + stack to a temp file.
	combined := append([]byte{}, dump.ExecData...)
	combined = append(combined, dump.StackData...)

	if len(combined) > ms.cfg.MaxDumpSize {
		combined = combined[:ms.cfg.MaxDumpSize]
	}

	if _, err := exec.LookPath(ms.cfg.YARABinary); err != nil {
		log.Printf("[memforensic] YARA binary not found: %v", err)
		return nil
	}

	// yara -w -m -j <rules> <dump_file>
	args := []string{"-w", "-m", "-j", "-s", ms.cfg.YARARulesPath}

	// Write to stdin pipe.
	cmd := exec.Command(ms.cfg.YARABinary, args...)
	cmd.Stdin = bytes.NewReader(combined)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Exit code 1 = matches found (not an error).
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				log.Printf("[memforensic] YARA error: %v", err)
				return nil
			}
		} else {
			log.Printf("[memforensic] YARA error: %v", err)
			return nil
		}
	}

	return parseYARAOutput(string(output))
}

func parseYARAOutput(output string) []ScanMatch {
	if output == "" {
		return nil
	}

	// YARA -j JSON output is an array of objects with "rule" and "matches".
	// For simplicity, parse line-based output as fallback.
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var matches []ScanMatch
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "rule_name [meta1=val1,meta2=val2] offset:hexbytes"
		parts := strings.SplitN(line, " ", 2)
		if len(parts) >= 1 {
			rule := strings.TrimSpace(parts[0])
			if rule == "" || rule == "[" {
				continue
			}
			severity := SevHigh
			if strings.Contains(strings.ToLower(rule), "cobalt") ||
				strings.Contains(strings.ToLower(rule), "beacon") {
				severity = SevCritical
			}
			matches = append(matches, ScanMatch{
				Rule:     rule,
				Severity: severity,
				Source:   "yara",
				Segment:  SegExec,
			})
		}
	}
	return matches
}

// ── Built-in hex pattern definitions ────────────────────────────

// hexPattern describes a known malicious byte sequence to search for.
type hexPattern struct {
	Name     string
	Hex      string
	Severity ScanSeverity
	Meta     map[string]string
}

func defaultHexPatterns() []hexPattern {
	return []hexPattern{
		// Cobalt Strike beacon indicators
		{
			Name:     "CS_BEACON_MUTEX",
			Hex:      "6d657373616765426f78", // "messageBox" (mutex pattern)
			Severity: SevCritical,
			Meta: map[string]string{
				"family": "cobalt_strike",
				"type":   "beacon_mutex",
			},
		},
		{
			Name:     "CS_BEACON_PIPE",
			Hex:      "5c5c2e5c706970655c",     // "\\.\pipe\"
			Severity: SevHigh,
			Meta: map[string]string{
				"family": "cobalt_strike",
				"type":   "named_pipe",
			},
		},
		{
			Name:     "CS_BEACON_CONFIG",
			Hex:      "0000000000000000000000000000000000000000", // 20 null bytes in beacon config
			Severity: SevMedium,
			Meta: map[string]string{
				"family": "cobalt_strike",
				"type":   "config_padding",
			},
		},
		// Meterpreter stager
		{
			Name:     "METERPRETER_STAGE",
			Hex:      "4d45544552505245544552", // "METERPETER"
			Severity: SevCritical,
			Meta: map[string]string{
				"family": "meterpreter",
				"type":   "stager",
			},
		},
		// Common shellcode: NOP sled
		{
			Name:     "NOP_SLED_LARGE",
			Hex:      "90909090909090909090909090909090", // 16+ NOPs
			Severity: SevLow,
			Meta: map[string]string{
				"family": "shellcode",
				"type":   "nop_sled",
			},
		},
		// ELF magic (suspicious when found in non-file-backed regions)
		{
			Name:     "ELF_MAGIC_ANON",
			Hex:      "7f454c46", // \x7fELF
			Severity: SevHigh,
			Meta: map[string]string{
				"family": "elf",
				"type":   "memory_elf",
			},
		},
		// forkbomb / exec shellcode patterns
		{
			Name:     "SHELLCODE_FORK",
			Hex:      "6a026a016a00", // push 2; push 1; push 0 (fork pattern)
			Severity: SevHigh,
			Meta: map[string]string{
				"family": "shellcode",
				"type":   "fork",
			},
		},
		// Reflective loader pattern (common in C2 payloads)
		{
			Name:     "REFLECTIVE_LOADER",
			Hex:      "4c8b2578000000", // lea r12, [rel some_offset]
			Severity: SevHigh,
			Meta: map[string]string{
				"family": "reflective_dll",
				"type":   "loader",
			},
		},
		// Encrypted/packed payload heuristic: high entropy marker
		{
			Name:     "RC4_KEY_SCHEDULE",
			Hex:      "0000000000000000000000000000000000000000000000000000000000000000", // 32 nulls = potential key schedule
			Severity: SevMedium,
			Meta: map[string]string{
				"family": "crypto",
				"type":   "key_schedule",
			},
		},
		// /dev/shm or memfd patterns in strings (fileless execution)
		{
			Name:     "MEMFD_REFERENCE",
			Hex:      "2f6465762f73686d2f", // "/dev/shm/"
			Severity: SevMedium,
			Meta: map[string]string{
				"family": "fileless",
				"type":   "memfd_exec",
			},
		},
		// execve("/bin/sh") shellcode pattern
		{
			Name:     "EXECVE_BINSH",
			Hex:      "2f62696e2f736800", // "/bin/sh\0"
			Severity: SevCritical,
			Meta: map[string]string{
				"family": "shellcode",
				"type":   "execve_binsh",
			},
		},
		// Bind shell port 4444 (common in Metasploit)
		{
			Name:     "BINDSHELL_4444",
			Hex:      "115c", // port 4444 in network byte order
			Severity: SevCritical,
			Meta: map[string]string{
				"family": "metasploit",
				"type":   "bind_shell",
				"port":   "4444",
			},
		},
		// PowerShell download cradle
		{
			Name:     "PS_DOWNLOAD_CRADLE",
			Hex:      "446f776e6c6f6164537472696e67", // "DownloadString"
			Severity: SevHigh,
			Meta: map[string]string{
				"family": "powershell",
				"type":   "download_cradle",
			},
		},
	}
}

// ── Hex pattern matching engine ─────────────────────────────────

func (ms *MemoryScanner) scanWithHexPatterns(dump *MemDumpResult) []ScanMatch {
	var matches []ScanMatch

	if len(dump.ExecData) > 0 {
		matches = append(matches, ms.matchInSegment(dump.ExecData, SegExec)...)
	}
	if len(dump.StackData) > 0 {
		matches = append(matches, ms.matchInSegment(dump.StackData, SegStack)...)
	}
	if len(dump.HeapData) > 0 {
		matches = append(matches, ms.matchInSegment(dump.HeapData, SegHeap)...)
	}

	return matches
}

func (ms *MemoryScanner) matchInSegment(data []byte, segType SegmentType) []ScanMatch {
	if len(data) == 0 {
		return nil
	}

	var matches []ScanMatch
	for _, pat := range ms.hexPatterns {
		needle, err := hex.DecodeString(pat.Hex)
		if err != nil || len(needle) == 0 {
			continue
		}

		offset := 0
		for {
			idx := bytes.Index(data[offset:], needle)
			if idx == -1 {
				break
			}
			matches = append(matches, ScanMatch{
				Rule:     pat.Name,
				Severity: pat.Severity,
				Offset:   uint64(offset + idx),
				Segment:  segType,
				Source:   "hex",
				Meta:     pat.Meta,
			})
			offset += idx + 1
			if offset >= len(data) {
				break
			}
		}
	}

	return matches
}

// ── Risk scoring ────────────────────────────────────────────────

// Severity weight for risk score calculation.
var severityWeight = map[ScanSeverity]float64{
	SevInfo:     0,
	SevLow:      5,
	SevMedium:   20,
	SevHigh:     40,
	SevCritical: 60,
}

func calcMatchRisk(matches []ScanMatch) float64 {
	if len(matches) == 0 {
		return 0
	}

	var score float64
	seenRules := make(map[string]bool)
	for _, m := range matches {
		if seenRules[m.Rule] {
			// Deduplicate, avoid double-counting same rule.
			continue
		}
		seenRules[m.Rule] = true
		if w, ok := severityWeight[m.Severity]; ok {
			score += w
		}
	}

	if score > 100 {
		score = 100
	}
	return score
}

func riskLevel(score float64) string {
	switch {
	case score >= 60:
		return "critical"
	case score >= 30:
		return "high"
	case score >= 10:
		return "medium"
	default:
		return "low"
	}
}
