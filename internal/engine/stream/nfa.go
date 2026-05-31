package stream

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// ═══════════════════════════════════════════════════════════════
// NFA-based APT pattern matching
//
// The NFA nondeterministically tracks multiple concurrent pattern
// matches.  Each event can trigger transitions in multiple active
// states, enabling detection of complex multi-step attack patterns.
//
// Example pattern (Living-off-the-Land):
//   state0 ─exec(curl)──▶ state1 ─file_write(/tmp/)──▶ state2 ─file_exec(/tmp/)──▶ ALERT
// ═══════════════════════════════════════════════════════════════

// PatternMatch is emitted when an NFA reaches an accepting state.
type PatternMatch struct {
	PatternID   string   `json:"pattern_id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	EventIDs    []string `json:"event_ids"`
	TTPRef      string   `json:"ttp_ref,omitempty"`
}

// NFAPattern defines a single APT pattern as a state machine.
type NFAPattern struct {
	ID          string
	Description string
	Severity    string
	TTPRef      string
	States      []NFAState
	StartState  int // index into States
	AcceptState int // index into States
}

// NFAState is a single state in the pattern automaton.
type NFAState struct {
	// Transitions from this state
	Transitions []NFATransition
}

// NFATransition defines an event-based state transition.
type NFATransition struct {
	EventType  syscall.EventType // event that triggers this transition
	CommMatch  string            // process comm pattern (empty = any)
	PathMatch  string            // path pattern (empty = any)
	NextState  int               // state index to transition to
}

// NFARunner tracks a single NFA instance for one process chain.
type NFARunner struct {
	State     int      // current state
	PID       uint32   // tracked PID
	EventIDs  []string // events that led here
	StepCount int
}

// NFAEngine manages all active NFA runners.
type NFAEngine struct {
	mu      sync.Mutex
	patterns []NFAPattern
	runners  []*NFARunner // active runners
	matches  []PatternMatch
}

// NewNFAEngine creates an NFA engine with default patterns.
func NewNFAEngine() *NFAEngine {
	e := &NFAEngine{}
	e.registerDefaultPatterns()
	return e
}

// registerDefaultPatterns registers built-in APT patterns.
func (ne *NFAEngine) registerDefaultPatterns() {
	ne.patterns = []NFAPattern{
		{
			ID: "LOL-EXEC",
			Description: "Living-off-the-Land: network tool downloads and executes script",
			Severity: "CRITICAL",
			TTPRef: "T1218,T1204",
			States: []NFAState{
				{ // state 0: initial
					Transitions: []NFATransition{
						{EventType: syscall.EventProcessFork, CommMatch: "curl", NextState: 1},
						{EventType: syscall.EventProcessFork, CommMatch: "wget", NextState: 1},
						{EventType: syscall.EventProcessFork, CommMatch: "nc", NextState: 1},
						{EventType: syscall.EventProcessFork, CommMatch: "python*", NextState: 1},
					},
				},
				{ // state 1: network tool executed
					Transitions: []NFATransition{
						{EventType: syscall.EventFileCreate, PathMatch: "/tmp/", NextState: 2},
						{EventType: syscall.EventFileModify, PathMatch: "/tmp/", NextState: 2},
					},
				},
				{ // state 2: file written to /tmp
					Transitions: []NFATransition{
						{EventType: syscall.EventProcessExec, PathMatch: "/tmp/", NextState: 3},
					},
				},
				// state 3: accepting — script executed from /tmp
			},
			StartState:  0,
			AcceptState: 3,
		},
		{
			ID: "SENSITIVE-READ",
			Description: "Sensitive file read by non-standard process",
			Severity: "HIGH",
			TTPRef: "T1003",
			States: []NFAState{
				{ // state 0
					Transitions: []NFATransition{
						{EventType: syscall.EventFileOpen, PathMatch: "/etc/shadow", NextState: 1},
						{EventType: syscall.EventFileOpen, PathMatch: "/etc/passwd", NextState: 1},
					},
				},
				// state 1: accepting — sensitive file accessed
			},
			StartState:  0,
			AcceptState: 1,
		},
		{
			ID: "NET-EXFIL",
			Description: "Process reads sensitive file then connects to external IP",
			Severity: "CRITICAL",
			TTPRef: "T1048",
			States: []NFAState{
				{ // state 0
					Transitions: []NFATransition{
						{EventType: syscall.EventFileOpen, PathMatch: "/etc/shadow", NextState: 1},
						{EventType: syscall.EventFileOpen, PathMatch: "/etc/passwd", NextState: 1},
					},
				},
				{ // state 1: sensitive file read
					Transitions: []NFATransition{
						{EventType: syscall.EventNetConnect, NextState: 2},
					},
				},
				// state 2: accepting — sensitive read + network = exfil
			},
			StartState:  0,
			AcceptState: 2,
		},
	}
}

// Ingest feeds an event into all active NFA runners.
// Returns any new pattern matches.
func (ne *NFAEngine) Ingest(evt *collector.Event) []*PatternMatch {
	ne.mu.Lock()
	defer ne.mu.Unlock()

	var newMatches []*PatternMatch

	// For each pattern, check if this event triggers a transition
	// in any existing runner, or creates a new runner
	for _, pattern := range ne.patterns {
		// Check existing runners
		for _, runner := range ne.runners {
			if ne.tryTransition(runner, &pattern, evt) {
				if runner.State == pattern.AcceptState {
					match := PatternMatch{
						PatternID:   pattern.ID,
						Description: pattern.Description,
						Severity:    pattern.Severity,
						EventIDs:    runner.EventIDs,
						TTPRef:      pattern.TTPRef,
					}
					newMatches = append(newMatches, &match)
					// Reset runner to start state for continued tracking
					runner.State = pattern.StartState
					log.Printf("[nfa] MATCH: %s (%s)", pattern.ID, pattern.Description)
				}
			}
		}

		// Check if this event starts a new runner from the initial state
		if ne.canStart(&pattern, evt) {
			runner := &NFARunner{
				State:    pattern.States[pattern.StartState].Transitions[0].NextState,
				PID:      evt.PID,
				EventIDs: []string{fmt.Sprintf("%s:%d", evt.Type.String(), evt.PID)},
			}
			ne.runners = append(ne.runners, runner)
			log.Printf("[nfa] new runner: pattern=%s pid=%d", pattern.ID, evt.PID)
		}
	}

	// Clean up old runners
	ne.cleanupRunners()

	return newMatches
}

// tryTransition checks if an event triggers a state transition.
func (ne *NFAEngine) tryTransition(runner *NFARunner, pattern *NFAPattern, evt *collector.Event) bool {
	if runner.State >= len(pattern.States) {
		return false
	}
	state := pattern.States[runner.State]
	for _, t := range state.Transitions {
		if !ne.matchesEvent(t, evt) {
			continue
		}
		if runner.PID != evt.PID && runner.PID != 0 {
			// PID mismatch — but allow if it's a child process
			// (fork events create new runners with the child PID)
		}
		runner.State = t.NextState
		runner.EventIDs = append(runner.EventIDs,
			fmt.Sprintf("%s:%d", evt.Type.String(), evt.PID))
		runner.StepCount++
		return true
	}
	return false
}

// canStart checks if an event can start a new runner for a pattern.
func (ne *NFAEngine) canStart(pattern *NFAPattern, evt *collector.Event) bool {
	if len(pattern.States) == 0 {
		return false
	}
	startState := pattern.States[pattern.StartState]
	for _, t := range startState.Transitions {
		if ne.matchesEvent(t, evt) {
			return true
		}
	}
	return false
}

// matchesEvent checks if an event matches a transition's criteria.
func (ne *NFAEngine) matchesEvent(t NFATransition, evt *collector.Event) bool {
	if t.EventType != 0 && t.EventType != evt.Type {
		return false
	}
	if t.CommMatch != "" && !wildcardMatch(t.CommMatch, evt.Comm) {
		return false
	}
	if t.PathMatch != "" && !wildcardMatch(t.PathMatch, evt.Pathname) {
		return false
	}
	return true
}

// wildcardMatch supports * wildcard matching.
func wildcardMatch(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(value, suffix)
	}
	return pattern == value
}

// cleanupRunners removes old/completed runners.
func (ne *NFAEngine) cleanupRunners() {
	var active []*NFARunner
	for _, r := range ne.runners {
		if r.StepCount < 20 { // max steps before cleanup
			active = append(active, r)
		}
	}
	ne.runners = active
}

// ActiveStates returns the number of active NFA runners.
func (ne *NFAEngine) ActiveStates() int {
	ne.mu.Lock()
	defer ne.mu.Unlock()
	return len(ne.runners)
}

// AddPattern registers a custom NFA pattern.
func (ne *NFAEngine) AddPattern(p NFAPattern) {
	ne.mu.Lock()
	defer ne.mu.Unlock()
	ne.patterns = append(ne.patterns, p)
}
