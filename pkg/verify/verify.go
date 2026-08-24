// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"
)

const (
	nodePrefix    = "n:"
	edgePrefix    = "e:"
	reversePrefix = "r:"
)

// CheckType identifies the kind of consistency check.
type CheckType int

const (
	CheckEdgeConsistency CheckType = iota // every e: has matching r: and vice versa
	CheckNodeReferences                   // every e:/r: source/target has a node
	CheckDiskUsage                        // disk usage statistics
)

func (ct CheckType) String() string {
	switch ct {
	case CheckEdgeConsistency:
		return "edge_consistency"
	case CheckNodeReferences:
		return "node_references"
	case CheckDiskUsage:
		return "disk_usage"
	default:
		return "unknown"
	}
}

// Issue represents a single consistency problem found.
type Issue struct {
	Type        CheckType `json:"type"`
	Key         string    `json:"key"`
	Message     string    `json:"message"`
	Fixable     bool      `json:"fixable"`
	ExpectedKey string    `json:"expected_key,omitempty"`
}

// Report is the complete verification result.
type Report struct {
	Timestamp    time.Time     `json:"timestamp"`
	Issues       []Issue       `json:"issues"`
	IssueCount   int           `json:"issue_count"`
	Repairable   int           `json:"repairable"`
	StorePath    string        `json:"store_path"`
	Duration     time.Duration `json:"duration"`
	DryRun       bool          `json:"dry_run"`
	NodeCount    int           `json:"node_count"`
	EdgeCount    int           `json:"edge_count"`
	ReverseCount int           `json:"reverse_count"`
	DiskBytes    int64         `json:"disk_bytes"`
}

// RunChecks opens the store and runs all consistency checks.
// If dryRun is true, issues are reported but no repair is attempted.
func RunChecks(storePath string, dryRun bool) (*Report, error) {
	start := time.Now()

	db, err := pebble.Open(storePath, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("open store %s: %w", storePath, err)
	}
	defer db.Close()

	r := &Report{
		Timestamp: time.Now(),
		StorePath: storePath,
		DryRun:    dryRun,
	}

	// Collect all keys by prefix for analysis
	nodeKeys := scanPrefix(db, nodePrefix)
	edgeKeys := scanPrefix(db, edgePrefix)
	reverseKeys := scanPrefix(db, reversePrefix)

	r.NodeCount = len(nodeKeys)
	r.EdgeCount = len(edgeKeys)
	r.ReverseCount = len(reverseKeys)

	m := db.Metrics()
	r.DiskBytes = int64(m.DiskSpaceUsage())

	// Check 1: Edge consistency — every e: must have a matching r:
	edgeMap := make(map[string]bool, len(edgeKeys))
	for _, k := range edgeKeys {
		edgeMap[k] = true
	}
	reverseMap := make(map[string]bool, len(reverseKeys))
	for _, k := range reverseKeys {
		reverseMap[k] = true
	}

	// For each e: key, derive the matching r: key format and check
	for _, ek := range edgeKeys {
		source, target, ts, ok := parseEdgeKeyV1(ek)
		if !ok {
			r.Issues = append(r.Issues, Issue{
				Type:    CheckEdgeConsistency,
				Key:     ek,
				Message: "unparseable edge key",
				Fixable: false,
			})
			continue
		}
		expectedReverse := reverseEdgeKeyV1(ts, target, source)
		if !reverseMap[expectedReverse] {
			r.Issues = append(r.Issues, Issue{
				Type:        CheckEdgeConsistency,
				Key:         ek,
				Message:     fmt.Sprintf("missing reverse edge: expected %s", expectedReverse),
				Fixable:     true,
				ExpectedKey: expectedReverse,
			})
		}
	}

	// For each r: key, derive the matching e: key and check
	for _, rk := range reverseKeys {
		source, target, ts, ok := parseReverseKeyV1(rk)
		if !ok {
			r.Issues = append(r.Issues, Issue{
				Type:    CheckEdgeConsistency,
				Key:     rk,
				Message: "unparseable reverse key",
				Fixable: false,
			})
			continue
		}
		expectedEdge := edgeKeyV1(ts, source, target)
		if !edgeMap[expectedEdge] {
			r.Issues = append(r.Issues, Issue{
				Type:        CheckEdgeConsistency,
				Key:         rk,
				Message:     fmt.Sprintf("missing forward edge: expected %s", expectedEdge),
				Fixable:     true,
				ExpectedKey: expectedEdge,
			})
		}
	}

	// Check 2: Node references — every edge source/target must have a node
	nodeSet := make(map[string]bool, len(nodeKeys))
	for _, k := range nodeKeys {
		nodeSet[k] = true
	}

	// Check from e: keys
	for _, ek := range edgeKeys {
		source, target, _, ok := parseEdgeKeyV1(ek)
		if !ok {
			continue
		}
		if !nodeSet[nodePrefix+source] {
			r.Issues = append(r.Issues, Issue{
				Type:    CheckNodeReferences,
				Key:     ek,
				Message: fmt.Sprintf("edge source %q has no node", source),
				Fixable: false,
			})
		}
		if !nodeSet[nodePrefix+target] {
			r.Issues = append(r.Issues, Issue{
				Type:    CheckNodeReferences,
				Key:     ek,
				Message: fmt.Sprintf("edge target %q has no node", target),
				Fixable: false,
			})
		}
	}

	// Check from r: keys
	for _, rk := range reverseKeys {
		source, target, _, ok := parseReverseKeyV1(rk)
		if !ok {
			continue
		}
		if !nodeSet[nodePrefix+source] {
			r.Issues = append(r.Issues, Issue{
				Type:    CheckNodeReferences,
				Key:     rk,
				Message: fmt.Sprintf("reverse edge source %q has no node", source),
				Fixable: false,
			})
		}
		if !nodeSet[nodePrefix+target] {
			r.Issues = append(r.Issues, Issue{
				Type:    CheckNodeReferences,
				Key:     rk,
				Message: fmt.Sprintf("reverse edge target %q has no node", target),
				Fixable: false,
			})
		}
	}

	r.IssueCount = len(r.Issues)
	for _, iss := range r.Issues {
		if iss.Fixable {
			r.Repairable++
		}
	}
	r.Duration = time.Since(start)

	return r, nil
}

// Repair fixes fixable issues found in a report.
// Currently supports:
//   - Missing reverse edges (creates them)
//   - Missing forward edges (creates them)
func Repair(report *Report, storePath string) error {
	db, err := pebble.Open(storePath, &pebble.Options{})
	if err != nil {
		return fmt.Errorf("open store %s: %w", storePath, err)
	}
	defer db.Close()

	batch := db.NewBatch()
	defer batch.Close()

	fixed := 0
	for _, iss := range report.Issues {
		if !iss.Fixable || iss.ExpectedKey == "" {
			continue
		}
		batch.Set([]byte(iss.ExpectedKey), []byte{}, pebble.Sync)
		fixed++
	}

	if err := batch.Commit(&pebble.WriteOptions{Sync: true}); err != nil {
		return fmt.Errorf("commit repair: %w", err)
	}

	return nil
}

// ── Key parsing ──────────────────────────────────────────────

// parseEdgeKeyV1 parses a v1 edge key "e:<020-ts>:<source>:<target>".
// Parses node IDs by consuming known patterns: <type>:<digits>(:<digits>)*
// where type is 'p' (process) or 'f' (file) followed by numeric components.
func parseEdgeKeyV1(key string) (source, target string, ts uint64, ok bool) {
	rest, found := strings.CutPrefix(key, edgePrefix)
	if !found || len(rest) < 22 {
		return "", "", 0, false
	}
	// First 20 chars are the zero-padded timestamp
	tsStr := rest[:20]
	if rest[20] != ':' {
		return "", "", 0, false
	}
	for _, c := range tsStr {
		if c < '0' || c > '9' {
			return "", "", 0, false
		}
	}
	fmt.Sscanf(tsStr, "%d", &ts)

	pair := rest[21:] // source:target
	source, target = splitNodePair(pair)
	if source == "" || target == "" {
		return "", "", 0, false
	}
	return source, target, ts, true
}

// splitNodePair splits a "source:target" string where both are node IDs of
// the form <type>:<digits>(:<digits>)* (e.g., "p:1234", "f:5000:8:3").
func splitNodePair(pair string) (source, target string) {
	// Consume source node ID char by char: <letter>:<digits>(:<digits>)*
	i := 0
	if len(pair) < 3 || (pair[i] != 'p' && pair[i] != 'f') {
		return "", ""
	}
	i++ // skip type letter
	if i >= len(pair) || pair[i] != ':' {
		return "", ""
	}
	i++ // skip ':'
	for i < len(pair) && pair[i] >= '0' && pair[i] <= '9' {
		i++
	}
	// Consume optional :<digits> groups (file device IDs)
	for i < len(pair) && pair[i] == ':' {
		next := i + 1
		if next < len(pair) && pair[next] >= '0' && pair[next] <= '9' {
			i = next
			for i < len(pair) && pair[i] >= '0' && pair[i] <= '9' {
				i++
			}
		} else {
			// This ':' is the source-target separator, not part of source
			break
		}
	}

	if i <= 0 || i >= len(pair) {
		return "", ""
	}
	source = pair[:i]
	target = pair[i+1:] // skip the ':' separator
	return source, target
}

// parseReverseKeyV1 parses "r:<target>:<020-ts>:<source>".
// Target is terminated by the 20-digit timestamp, making this unambiguous.
func parseReverseKeyV1(key string) (source, target string, ts uint64, ok bool) {
	rest, found := strings.CutPrefix(key, reversePrefix)
	if !found || len(rest) < 23 {
		return "", "", 0, false
	}

	// Find the timestamp: 20 consecutive digits preceded by ':'
	// The target ends before the ':' + 20 digits.
	// Scan for ":<20 digits>:" pattern
	tsStart := -1
	for i := 0; i <= len(rest)-22; i++ {
		if rest[i] == ':' {
			// Check if next 20 chars are all digits
			allDigits := true
			for j := 0; j < 20; j++ {
				if rest[i+1+j] < '0' || rest[i+1+j] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits && i+21 < len(rest) && rest[i+21] == ':' {
				tsStart = i + 1
				break
			}
		}
	}
	if tsStart < 0 {
		return "", "", 0, false
	}

	target = rest[:tsStart-1] // everything before the ':' before timestamp
	tsStr := rest[tsStart : tsStart+20]
	fmt.Sscanf(tsStr, "%d", &ts)
	source = rest[tsStart+21:] // after ts + ':'

	if target == "" || source == "" {
		return "", "", 0, false
	}
	return source, target, ts, true
}

func edgeKeyV1(ts uint64, source, target string) string {
	return fmt.Sprintf("e:%020d:%s:%s", ts, source, target)
}

func reverseEdgeKeyV1(ts uint64, target, source string) string {
	return fmt.Sprintf("r:%s:%020d:%s", target, ts, source)
}

// ── Helpers ──────────────────────────────────────────────────

// scanPrefix returns all keys in the database with the given prefix.
func scanPrefix(db *pebble.DB, prefix string) []string {
	lo := []byte(prefix)
	hi := []byte(prefix[:len(prefix)-1] + string(prefix[len(prefix)-1]+1))

	iter, err := db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return nil
	}
	defer iter.Close()

	var out []string
	for iter.First(); iter.Valid(); iter.Next() {
		out = append(out, string(iter.Key()))
	}
	return out
}
