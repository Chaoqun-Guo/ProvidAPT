package compact

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Semantic summary generation
//
// For provenance data older than 7 days, fine-grained I/O events
// are abstracted into behaviour summaries that preserve causality
// while dramatically reducing storage.
//
// Example:
//   100,000 raw events:
//     read(nginx, access.log) x 50000
//     write(nginx, access.log) x 50000
//
//   Summary:
//     [Process: nginx] [File: access.log] [R+W 1.2GB]
//     [Time range: 2025-01-01T00:00 ~ 2025-01-01T23:59]
//     [Interactions: 100,000]
// ═══════════════════════════════════════════════════════════════

// BehaviourSummary is a compact representation of many I/O events.
type BehaviourSummary struct {
	ProcessID     string `json:"process_id"`
	ProcessComm   string `json:"process_comm"`
	TargetEntity  string `json:"target_entity"`
	TargetType    string `json:"target_type"`
	Operation     string `json:"operation"` // "READ", "WROTE", "R+W"
	TotalCalls    int64  `json:"total_calls"`
	TotalBytes    int64  `json:"total_bytes_estimated"`
	TimeStart     string `json:"time_start"`
	TimeEnd       string `json:"time_end"`
	FirstEventID  string `json:"first_event_id,omitempty"`
	LastEventID   string `json:"last_event_id,omitempty"`
}

// SummaryConfig controls summary generation.
type SummaryConfig struct {
	// MinEventsForSummary — minimum events to create a summary.
	MinEventsForSummary int

	// SummaryAge — events older than this get summarised.
	SummaryAge time.Duration

	// GroupByProcess — group by process identity.
	GroupByProcess bool
}

// DefaultSummaryConfig returns sensible defaults.
func DefaultSummaryConfig() *SummaryConfig {
	return &SummaryConfig{
		MinEventsForSummary: 1000,
		SummaryAge:          7 * 24 * time.Hour, // 7 days
		GroupByProcess:      true,
	}
}

// SummaryEngine generates behaviour summaries from old data.
type SummaryEngine struct {
	cfg *SummaryConfig
}

// NewSummaryEngine creates a summary generator.
func NewSummaryEngine(cfg *SummaryConfig) *SummaryEngine {
	if cfg == nil {
		cfg = DefaultSummaryConfig()
	}
	return &SummaryEngine{cfg: cfg}
}

// SummariseEdges groups edges by (process, target, operation) and
// creates compact summaries for old data.
func (se *SummaryEngine) SummariseEdges(edges []*provenance.Edge, nodes []*provenance.Node) []*BehaviourSummary {
	cutoff := time.Now().Add(-se.cfg.SummaryAge)

groups := make(map[groupKey][]*provenance.Edge)

	for _, e := range edges {
		if e.Timestamp.After(cutoff) {
			continue // skip recent data
		}
		key := groupKey{e.Source, e.Target, e.Relation}
		groups[key] = append(groups[key], e)
	}

	var summaries []*BehaviourSummary
	for key, group := range groups {
		if len(group) < se.cfg.MinEventsForSummary {
			continue // too few events, keep raw
		}

		summary := se.buildSummary(key, group, nodes)
		summary.TotalCalls = int64(len(group))

		// Estimate total bytes: each event ≈ 332 bytes of I/O
		summary.TotalBytes = int64(len(group)) * 332

		// Time range
		summary.TimeStart = group[0].Timestamp.Format(time.RFC3339)
		summary.TimeEnd = group[len(group)-1].Timestamp.Format(time.RFC3339)

		summary.FirstEventID = group[0].ID
		summary.LastEventID = group[len(group)-1].ID

		summaries = append(summaries, summary)
	}

	log.Printf("[compact] generated %d behaviour summaries from %d edge groups",
		len(summaries), len(groups))

	return summaries
}

// groupKey is the composite key for grouping edges by source/target/relation.
type groupKey struct {
	source, target, relation string
}

// buildSummary creates a single BehaviourSummary from a group.
func (se *SummaryEngine) buildSummary(key groupKey, group []*provenance.Edge,
	nodes []*provenance.Node) *BehaviourSummary {

	summary := &BehaviourSummary{
		ProcessID: key.source,
	}

	// Resolve process comm
	for _, n := range nodes {
		if n.ID == key.source {
			summary.ProcessComm = n.Label
		}
		if n.ID == key.target {
			summary.TargetEntity = n.Label
			summary.TargetType = n.Subtype
		}
	}

	// Determine operation
	switch key.relation {
	case "prov:used":
		summary.Operation = "READ"
	case "prov:wasGeneratedBy":
		summary.Operation = "WROTE"
	default:
		summary.Operation = key.relation
	}

	return summary
}

// SummaryText returns a human-readable summary line.
func (bs *BehaviourSummary) SummaryText() string {
	return fmt.Sprintf("[%s] %s %s %s x%d (%.1f MB, %s ~ %s)",
		bs.ProcessComm, bs.Operation, bs.TargetEntity, bs.TargetType,
		bs.TotalCalls, float64(bs.TotalBytes)/1024/1024,
		bs.TimeStart, bs.TimeEnd)
}

// CompactionResult holds the combined reduction + summary result.
type CompactionResult struct {
	Reduction *ReductionMetrics   `json:"reduction"`
	Summaries []*BehaviourSummary `json:"summaries"`
	EdgesRemoved int             `json:"edges_removed"`
	StorageSaved int64           `json:"storage_saved_bytes"`
}

// Combine returns a combined result from reduction and summary.
func Combine(reduction *ReductionMetrics, summaries []*BehaviourSummary) *CompactionResult {
	result := &CompactionResult{
		Reduction:    reduction,
		Summaries:    summaries,
		EdgesRemoved: reduction.EdgesRemoved,
	}
	for _, s := range summaries {
		result.StorageSaved += s.TotalBytes
		result.EdgesRemoved += int(s.TotalCalls)
	}
	result.StorageSaved += reduction.StorageSaved
	return result
}

// Summary returns a human-readable compaction result.
func (cr *CompactionResult) Summary() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Compaction: %d edges removed, %.1f MB saved\n",
		cr.EdgesRemoved, float64(cr.StorageSaved)/1024/1024))
	if cr.Reduction != nil {
		b.WriteString(fmt.Sprintf("  Reduction: %s\n", cr.Reduction.Summary()))
	}
	b.WriteString(fmt.Sprintf("  Summaries: %d behaviour summaries\n", len(cr.Summaries)))
	return b.String()
}
