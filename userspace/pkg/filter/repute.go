package filter

import (
	"path/filepath"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// Path reputation scoring
//
// Every file path and process comm receives a reputation score from
// 0 (lowest trust) to 100 (highest trust).  High-reputation paths
// produce events that are aggressively compressed/merged; low-
// reputation paths (e.g. /tmp, /dev/shm) are always fully recorded.
// ═══════════════════════════════════════════════════════════════

// Default reputation rules.  Earlier entries have higher priority.
var defaultRules = []RepRule{
	// Process comm (binary name) rules
	{Pattern: "*", Field: "comm", Score: 50, Priority: 0}, // default

	{Pattern: "systemd*", Field: "comm", Score: 95, Priority: 10},
	{Pattern: "kernel*", Field: "comm", Score: 95, Priority: 10},
	{Pattern: "sshd", Field: "comm", Score: 70, Priority: 10},
	{Pattern: "sshd", Field: "comm", Score: 70, Priority: 10},
	{Pattern: "sshd", Field: "comm", Score: 70, Priority: 10},

	// Core system binaries
	{Pattern: "systemd*", Field: "path", Score: 95, Priority: 10},
	{Pattern: "/usr/bin/*", Field: "path", Score: 85, Priority: 5},
	{Pattern: "/bin/*", Field: "path", Score: 85, Priority: 5},
	{Pattern: "/usr/sbin/*", Field: "path", Score: 85, Priority: 5},
	{Pattern: "/sbin/*", Field: "path", Score: 85, Priority: 5},
	{Pattern: "/usr/lib/*", Field: "path", Score: 80, Priority: 5},

	// System logs and configuration
	{Pattern: "/var/log/*", Field: "path", Score: 60, Priority: 3},
	{Pattern: "/etc/*", Field: "path", Score: 50, Priority: 3},

	// User data — medium trust
	{Pattern: "/home/*", Field: "path", Score: 40, Priority: 2},
	{Pattern: "/var/www/*", Field: "path", Score: 30, Priority: 2},

	// Temporary / untrusted
	{Pattern: "/tmp/*", Field: "path", Score: 5, Priority: 10},
	{Pattern: "/dev/shm/*", Field: "path", Score: 5, Priority: 10},
	{Pattern: "/var/tmp/*", Field: "path", Score: 5, Priority: 10},
	{Pattern: "/proc/*", Field: "path", Score: 10, Priority: 5},

	// High-risk processes
	{Pattern: "nc", Field: "comm", Score: 10, Priority: 10},
	{Pattern: "ncat", Field: "comm", Score: 10, Priority: 10},
	{Pattern: "tftp", Field: "comm", Score: 10, Priority: 10},
	{Pattern: "curl", Field: "comm", Score: 30, Priority: 5},
	{Pattern: "wget", Field: "comm", Score: 30, Priority: 5},
	{Pattern: "python*", Field: "comm", Score: 30, Priority: 5},
	{Pattern: "bash", Field: "comm", Score: 40, Priority: 5},
}

// RepRule is a single reputation rule.
type RepRule struct {
	Pattern  string // glob pattern
	Field    string // "comm" or "path"
	Score    int    // 0–100
	Priority int    // higher = overrides lower
}

// Reputation scores paths and process names.
type Reputation struct {
	rules []RepRule
}

// NewReputation creates a reputation scorer with default rules.
func NewReputation() *Reputation {
	r := &Reputation{rules: defaultRules}
	sort.Slice(r.rules, func(i, j int) bool {
		return r.rules[i].Priority > r.rules[j].Priority
	})
	return r
}

// ScoreComm returns the reputation of a process comm name (0–100).
func (r *Reputation) ScoreComm(comm string) int {
	for _, rule := range r.rules {
		if rule.Field != "comm" {
			continue
		}
		if matched, _ := filepath.Match(rule.Pattern, comm); matched {
			return rule.Score
		}
	}
	return 50
}

// ScorePath returns the reputation of a file path (0–100).
func (r *Reputation) ScorePath(path string) int {
	for _, rule := range r.rules {
		if rule.Field != "path" {
			continue
		}
		if matched, _ := filepath.Match(rule.Pattern, path); matched {
			return rule.Score
		}
	}
	return 50
}

// Classify returns a human-readable trust level.
func (r *Reputation) Classify(score int) string {
	switch {
	case score >= 80:
		return "trusted"
	case score >= 50:
		return "normal"
	case score >= 20:
		return "suspicious"
	default:
		return "untrusted"
	}
}

// AddRule adds a custom reputation rule.
func (r *Reputation) AddRule(pattern, field string, score, priority int) {
	r.rules = append(r.rules, RepRule{
		Pattern: pattern, Field: field, Score: score, Priority: priority,
	})
	sort.Slice(r.rules, func(i, j int) bool {
		return r.rules[i].Priority > r.rules[j].Priority
	})
}

// ── Reputation thresholds ───────────────────────────────────

const (
	RepThresholdLow    = 20  // below this: always persist
	RepThresholdMedium = 50  // below this: normal processing
	RepThresholdHigh   = 80  // above this: aggressive merge
)

// ShouldAggressivelyMerge returns true if events from paths with
// this score should be heavily compressed (memory-only counters).
func ShouldAggressivelyMerge(score int) bool {
	return score >= RepThresholdHigh
}

// IsUntrusted returns true if the score indicates a high-risk path.
func IsUntrusted(score int) bool {
	return score < RepThresholdLow
}
