// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package appsync

import (
	"fmt"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Semantic node merging
//
// Aggregates scattered system call nodes into logical "transaction
// nodes" that represent high-level user actions.
//
// Example transformation:
//
//   BEFORE:  connect() → write() → read() → close()  [4 syscall nodes]
//   AFTER:   [HTTP GET /admin/config]  [1 transaction node]
//
// The transaction node is added to the provenance graph as a
// "transaction" subtype entity, with edges to the participating
// process, files, and network endpoints.
// ═══════════════════════════════════════════════════════════════

// TransactionNode represents a merged application-level transaction.
type TransactionNode struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`       // "HTTP GET /admin/config"
	Method     string    `json:"method"`      // HTTP method or SQL command
	Path       string    `json:"path"`        // URL path or query
	RequestID  string    `json:"request_id"`
	PID        uint32    `json:"pid"`
	TID        uint32    `json:"tid"`
	AppName    string    `json:"app_name"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time,omitempty"`
	Duration   string    `json:"duration,omitempty"`

	// Associated resources identified during this transaction
	FilesRead    []string `json:"files_read,omitempty"`
	FilesWritten []string `json:"files_written,omitempty"`
	NetConnects  []string `json:"net_connects,omitempty"`
	ChildProcs   []string `json:"child_processes,omitempty"`
}

// SemanticMerger aggregates syscall events into transaction nodes.
type SemanticMerger struct {
	mu         sync.Mutex
	pending    map[string]*TransactionNode // requestID → pending txn
	completed  []*TransactionNode
	txnCounter int
}

// NewSemanticMerger creates a transaction merger.
func NewSemanticMerger() *SemanticMerger {
	return &SemanticMerger{
		pending: make(map[string]*TransactionNode),
	}
}

// BeginTransaction starts a new transaction from a request.
func (sm *SemanticMerger) BeginTransaction(info *RequestInfo) *TransactionNode {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.txnCounter++
	id := fmt.Sprintf("txn:%d", sm.txnCounter)
	label := fmt.Sprintf("%s %s", info.Method, info.Path)
	if info.Query != "" {
		label = fmt.Sprintf("%s:%s", info.Method, info.Query)
	}

	txn := &TransactionNode{
		ID:        id,
		Label:     label,
		Method:    info.Method,
		Path:      info.Path,
		RequestID: info.RequestID,
		PID:       info.PID,
		TID:       info.TID,
		AppName:   info.AppName,
		StartTime: info.StartTime,
	}

	sm.pending[info.RequestID] = txn
	return txn
}

// EndTransaction completes a pending transaction.
func (sm *SemanticMerger) EndTransaction(requestID string) *TransactionNode {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	txn, ok := sm.pending[requestID]
	if !ok {
		return nil
	}

	txn.EndTime = time.Now()
	txn.Duration = txn.EndTime.Sub(txn.StartTime).String()
	delete(sm.pending, requestID)
	sm.completed = append(sm.completed, txn)
	return txn
}

// RecordFileAccess associates a file access with the current transaction.
func (sm *SemanticMerger) RecordFileAccess(tid uint32, tracker *RequestTracker, path string, isWrite bool) {
	req := tracker.GetRequest(tid)
	if req == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	txn, ok := sm.pending[req.RequestID]
	if !ok {
		return
	}

	if isWrite {
		txn.FilesWritten = append(txn.FilesWritten, path)
	} else {
		txn.FilesRead = append(txn.FilesRead, path)
	}
}

// RecordNetworkConnect associates a network connection with the current transaction.
func (sm *SemanticMerger) RecordNetworkConnect(tid uint32, tracker *RequestTracker, addr string) {
	req := tracker.GetRequest(tid)
	if req == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	txn, ok := sm.pending[req.RequestID]
	if !ok {
		return
	}
	txn.NetConnects = append(txn.NetConnects, addr)
}

// BuildGraphNode creates a provenance graph node for a transaction.
func (txn *TransactionNode) BuildGraphNode() *provenance.Node {
	n := &provenance.Node{
		ID:         txn.ID,
		ProvType:   "prov:Activity",
		Subtype:    "transaction",
		Label:      txn.Label,
		FirstSeen:  txn.StartTime,
		LastSeen:   txn.EndTime,
		Attributes: make(map[string]interface{}),
	}
	n.Attributes["method"] = txn.Method
	n.Attributes["path"] = txn.Path
	n.Attributes["request_id"] = txn.RequestID
	n.Attributes["app"] = txn.AppName
	n.Attributes["duration"] = txn.Duration
	n.Attributes["pid"] = txn.PID
	return n
}

// CompletedTransactions returns all completed transactions.
func (sm *SemanticMerger) CompletedTransactions() []*TransactionNode {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	out := make([]*TransactionNode, len(sm.completed))
	copy(out, sm.completed)
	return out
}

// PendingCount returns the number of in-flight transactions.
func (sm *SemanticMerger) PendingCount() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return len(sm.pending)
}

// Summary returns a human-readable summary of merged transactions.
func (sm *SemanticMerger) Summary() string {
	completed := len(sm.completed)
	pending := len(sm.pending)

	var samples []string
	for _, txn := range sm.completed {
		if len(samples) >= 5 {
			break
		}
		label := txn.Label
		if len(label) > 60 {
			label = label[:57] + "..."
		}
		files := len(txn.FilesRead) + len(txn.FilesWritten)
		samples = append(samples, fmt.Sprintf("    %s (%s, %d files, %d net)",
			label, txn.Duration, files, len(txn.NetConnects)))
	}

	summary := fmt.Sprintf("Transactions: %d completed, %d pending\n", completed, pending)
	for _, s := range samples {
		summary += s + "\n"
	}
	return summary
}
