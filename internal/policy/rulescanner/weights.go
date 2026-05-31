// Package detect — weight model and path aggregation for
// composite alerting.  Each operation type has a base score;
// when a process's downstream path exceeds the threshold,
// a composite alert fires with full provenance context.
package rulescanner

import (
	"fmt"
	"strings"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
	store "github.com/Chaoqun-Guo/ProvidAPT/internal/storage/pebblestore"
)

// ═══════════════════════════════════════════════════════════════
// Score definitions
// ═══════════════════════════════════════════════════════════════

// EventScores maps event types to base threat scores.
// These scores represent the intrinsic risk of each operation.
var EventScores = map[uint32]float64{
	1:  5,   // EV_PROCESS_FORK
	2:  20,  // EV_PROCESS_EXEC — executing any binary
	10: 2,   // EV_FILE_OPEN — reading a file (low)
	11: 15,  // EV_FILE_CREATE — creating a file
	12: 10,  // EV_FILE_MODIFY — modifying a file
	13: 5,   // EV_FILE_DELETE
	20: 10,  // EV_NET_CONNECT — network connection
	21: 15,  // EV_NET_ACCEPT — inbound connection
	50: 60,  // EV_MEMFD_CREATE — anonymous memory file (suspicious)
	51: 100, // EV_MPROTECT_RX — memory shellcode injection
	52: 20,  // EV_PIPE_WRITE — pipe data flow
	53: 20,  // EV_PIPE_READ — pipe data flow
}

// SensitivePathScores provides additional scoring for file paths.
var SensitivePathScores = []PathScore{
	{Pattern: "/etc/shadow", Score: 50},
	{Pattern: "/etc/passwd", Score: 40},
	{Pattern: "/etc/sudoers", Score: 50},
	{Pattern: "/root/.ssh/", Score: 60},
	{Pattern: "/.aws/credentials", Score: 70},
	{Pattern: "/tmp/", Score: 5},
	{Pattern: "/dev/shm/", Score: 10},
}

// PathScore pairs a path pattern with an additional score.
type PathScore struct {
	Pattern string
	Score   float64
}

// Threshold for composite alerting
const CompositeThreshold = 150.0
const TraceDepth = 3

// ═══════════════════════════════════════════════════════════════
// Scoring engine
// ═══════════════════════════════════════════════════════════════

// ScoreEngine assigns scores to events and aggregates them
// along provenance paths.
type ScoreEngine struct {
	store *store.Store
	scores map[uint32]float64
	pathScores []PathScore
}

// NewScoreEngine creates a scoring engine with default weights.
func NewScoreEngine(st *store.Store) *ScoreEngine {
	s := make(map[uint32]float64)
	for k, v := range EventScores {
		s[k] = v
	}
	ps := make([]PathScore, len(SensitivePathScores))
	copy(ps, SensitivePathScores)
	return &ScoreEngine{
		store:      st,
		scores:     s,
		pathScores: ps,
	}
}

// ScoreEvent computes the threat score for a single event.
func (se *ScoreEngine) ScoreEvent(evt *pb.Event) float64 {
	base := se.scores[evt.Type]

	// Add path-based scoring
	for _, ps := range se.pathScores {
		if strings.HasPrefix(evt.Pathname, ps.Pattern) {
			base += ps.Score
			break
		}
	}

	return base
}

// ═══════════════════════════════════════════════════════════════
// Path weight aggregation
// ═══════════════════════════════════════════════════════════════

// AggregateResult collects the cumulative score and causal chain.
type AggregateResult struct {
	ProcessPID     uint32          `json:"process_pid"`
	ProcessComm    string          `json:"process_comm"`
	CumulativeScore float64        `json:"cumulative_score"`
	EventCount     int             `json:"event_count"`
	ExceedsThreshold bool          `json:"exceeds_threshold"`
	CausalChain    []CausalNode    `json:"causal_chain"`
}

// CausalNode is a single step in the provenance trace-back.
type CausalNode struct {
	PID    uint32  `json:"pid"`
	Comm   string  `json:"comm"`
	Action string  `json:"action"`
	Target string  `json:"target"`
	Score  float64 `json:"score"`
}

// AggregatePath walks the provenance graph from a process and
// accumulates scores along the downstream path.  If the total
// exceeds CompositeThreshold, a composite alert is indicated.
//
// It also extracts the top 3 causal ancestor nodes for context.
func (se *ScoreEngine) AggregatePath(evt *pb.Event) *AggregateResult {
	result := &AggregateResult{
		ProcessPID:  evt.Pid,
		ProcessComm: evt.Comm,
	}

	// Score the immediate event
	immediateScore := se.ScoreEvent(evt)
	result.CumulativeScore = immediateScore
	result.CausalChain = append(result.CausalChain, CausalNode{
		PID:    evt.Pid,
		Comm:   evt.Comm,
		Action: eventTypeName(evt.Type),
		Target: evt.Pathname,
		Score:  immediateScore,
	})

	// Trace backward through causal ancestors (up to TraceDepth)
	// using the process's parent information.
	currentPID := evt.Pid
	for depth := 0; depth < TraceDepth; depth++ {
		// Get the parent process by querying the store
		if se.store == nil {
			break
		}
		node, err := se.store.GetNodeByPID(currentPID)
		if err != nil || node == nil {
			break
		}

		// Read the parent PID from node attributes
		parentPID := node.Ppid
		if parentPID == 0 || parentPID == currentPID {
			break
		}

		// Get parent node for scoring
		parent, err := se.store.GetNodeByPID(parentPID)
		if err != nil || parent == nil {
			break
		}

		// Assign a notional score for the parent relationship
		parentScore := 5.0 // fork/baseline

		// Try to find edges between parent and child for more accurate scoring
		edges, err := se.store.GetEdgesBySource(fmt.Sprintf("p:%d", parentPID))
		if err == nil {
			for _, e := range edges {
				if e.Target == fmt.Sprintf("p:%d", currentPID) {
					parentScore = float64(e.Count) * 2.0
				}
			}
		}

		result.CumulativeScore += parentScore
		result.CausalChain = append(result.CausalChain, CausalNode{
			PID:    parentPID,
			Comm:   parent.Comm,
			Action: "forked",
			Target: parent.Comm,
			Score:  parentScore,
		})

		currentPID = parentPID
	}

	result.EventCount = len(result.CausalChain)
	result.ExceedsThreshold = result.CumulativeScore >= CompositeThreshold

	return result
}

// ═══════════════════════════════════════════════════════════════
// Composite alert
// ═══════════════════════════════════════════════════════════════

// CompositeAlert is emitted when a process's downstream path
// exceeds the risk threshold.
type CompositeAlert struct {
	ProcessPID     uint32       `json:"process_pid"`
	ProcessComm    string       `json:"process_comm"`
	TotalScore     float64      `json:"total_score"`
	Threshold      float64      `json:"threshold"`
	TriggerEvent   string       `json:"trigger_event"`
	CausalChain    []CausalNode `json:"causal_chain"`
}

// NewCompositeAlert creates a composite alert from an aggregate result.
func NewCompositeAlert(evt *pb.Event, agg *AggregateResult) *CompositeAlert {
	return &CompositeAlert{
		ProcessPID:   evt.Pid,
		ProcessComm:  evt.Comm,
		TotalScore:   agg.CumulativeScore,
		Threshold:    CompositeThreshold,
		TriggerEvent: fmt.Sprintf("%s → %s", eventTypeName(evt.Type), evt.Pathname),
		CausalChain:  agg.CausalChain,
	}
}

// String returns a human-readable composite alert.
func (ca *CompositeAlert) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("🚨 COMPOSITE ALERT — Score: %.0f / %.0f\n",
		ca.TotalScore, ca.Threshold))
	b.WriteString(fmt.Sprintf("   Process: %s (PID %d)\n", ca.ProcessComm, ca.ProcessPID))
	b.WriteString(fmt.Sprintf("   Trigger: %s\n", ca.TriggerEvent))
	b.WriteString("   Causal Chain:\n")
	for i, node := range ca.CausalChain {
		marker := "└─"
		if i < len(ca.CausalChain)-1 {
			marker = "├─"
		}
		b.WriteString(fmt.Sprintf("   %s [%.0f] %s (PID %d) %s → %s\n",
			marker, node.Score, node.Comm, node.PID, node.Action, node.Target))
	}
	return b.String()
}
