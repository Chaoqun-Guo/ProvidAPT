package forensic

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// YARA scanning
// ═══════════════════════════════════════════════════════════════

// YARAResult holds the outcome of a YARA scan.
type YARAResult struct {
	ScannedPath string     `json:"scanned_path"`
	RulesCount  int        `json:"rules_count"`
	Matches     []YARAMatch `json:"matches,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// YARAMatch is a single rule match from a YARA scan.
type YARAMatch struct {
	Rule      string `json:"rule"`
	Namespace string `json:"namespace,omitempty"`
	Tags      string `json:"tags,omitempty"`
	Meta      string `json:"meta,omitempty"`
}

// YARAConfig configures the YARA scanner.
type YARAConfig struct {
	RulesPath string // path to YARA rules file or directory
	Binary    string // yara executable path (default: "yara")
	Timeout   int    // scan timeout in seconds (default: 30)
}

// DefaultYARAConfig uses the system yara binary.
func DefaultYARAConfig() *YARAConfig {
	return &YARAConfig{
		Binary:    "yara",
		Timeout:   30,
	}
}

// YARAScanner scans files and memory with YARA rules.
type YARAScanner struct {
	cfg *YARAConfig
}

// NewYARAScanner creates a YARA scanner.
func NewYARAScanner(cfg *YARAConfig) *YARAScanner {
	if cfg == nil {
		cfg = DefaultYARAConfig()
	}
	return &YARAScanner{cfg: cfg}
}

// ScanFile runs YARA rules against a file on disk.
func (ys *YARAScanner) ScanFile(path string) *YARAResult {
	result := &YARAResult{ScannedPath: path}

	if ys.cfg.RulesPath == "" {
		result.Error = "no YARA rules configured"
		return result
	}

	if _, err := exec.LookPath(ys.cfg.Binary); err != nil {
		result.Error = fmt.Sprintf("yara binary not found: %v", err)
		return result
	}

	// Build command: yara -w -m <rules> <file>
	args := []string{"-w", "-m", "-j", ys.cfg.RulesPath, path}
	cmd := exec.Command(ys.cfg.Binary, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Exit code 1 means matches found (not a real error)
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				result.Error = fmt.Sprintf("yara error: %v", err)
				return result
			}
		} else {
			result.Error = fmt.Sprintf("yara error: %v", err)
			return result
		}
	}

	// Parse JSON output
	// YARA 4.x JSON output is an array of match objects
	var matches []YARAMatch
	if err := json.Unmarshal(output, &matches); err != nil {
		// Fallback: parse text output
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) >= 1 {
				matches = append(matches, YARAMatch{Rule: strings.TrimSpace(parts[0])})
			}
		}
	}

	result.RulesCount = len(matches)
	result.Matches = matches
	return result
}

// ScanMemory runs YARA rules against a process's memory.
// This requires a YARA rule set that can scan /proc/<pid>/mem
// or uses process_vm_readv.
func (ys *YARAScanner) ScanMemory(pid int) *YARAResult {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	result := ys.ScanFile(memPath)

	if result.Error != "" {
		// Fallback: try reading /proc/<pid>/exe
		exePath := fmt.Sprintf("/proc/%d/exe", pid)
		return ys.ScanFile(exePath)
	}
	return result
}

// IsAvailable checks if YARA is installed and rules are configured.
func (ys *YARAScanner) IsAvailable() bool {
	if _, err := exec.LookPath(ys.cfg.Binary); err != nil {
		return false
	}
	if ys.cfg.RulesPath == "" {
		return false
	}
	_, err := exec.LookPath(ys.cfg.RulesPath)
	if err != nil {
		_, err := os.Stat(ys.cfg.RulesPath)
		return err == nil
	}
	return true
}
