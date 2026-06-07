// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package netmon

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// TCP state tracking
// ═══════════════════════════════════════════════════════════════

// TCP states (matching kernel include/net/tcp_states.h)
const (
	TCP_ESTABLISHED = 1
	TCP_SYN_SENT    = 2
	TCP_SYN_RECV    = 3
	TCP_FIN_WAIT1   = 4
	TCP_FIN_WAIT2   = 5
	TCP_TIME_WAIT   = 6
	TCP_CLOSE       = 7
	TCP_CLOSE_WAIT  = 8
	TCP_LAST_ACK    = 9
	TCP_LISTEN      = 10
	TCP_CLOSING     = 11
)

var tcpStateNames = map[int]string{
	1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV",
	4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
	7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK",
	10: "LISTEN", 11: "CLOSING",
}

func tcpStateName(state int) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}

// SocketKey uniquely identifies a TCP connection.
type SocketKey struct {
	SrcIP   string
	SrcPort uint32
	DstIP   string
	DstPort uint32
}

func (k SocketKey) String() string {
	return fmt.Sprintf("%s:%d-%s:%d", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
}

// SocketState tracks the full lifecycle of a TCP connection.
type SocketState struct {
	Key        SocketKey   `json:"key"`
	State      int         `json:"state"`
	StateName  string      `json:"state_name"`
	PID        uint32      `json:"pid"`
	Comm       string      `json:"comm"`

	// Timestamps for each state transition
	SYNSent    time.Time   `json:"syn_sent,omitempty"`
	SYNRecv    time.Time   `json:"syn_recv,omitempty"`
	Established time.Time  `json:"established,omitempty"`
	Closed     time.Time   `json:"closed,omitempty"`

	// Duration metrics
	HandshakeDuration string `json:"handshake_duration,omitempty"` // SYN→EST
	ConnectionDuration string `json:"connection_duration,omitempty"` // EST→CLOSE

	// Metadata
	Domain      string `json:"domain,omitempty"`  // from DNS cache
	HTTPHost    string `json:"http_host,omitempty"` // from HTTP analysis
	HTTPPath    string `json:"http_path,omitempty"`
}

// SocketTracker maintains the state of all tracked TCP connections.
type SocketTracker struct {
	mu      sync.Mutex
	sockets map[SocketKey]*SocketState
	dns     *DNSCache
	history []*SocketState // completed connections
}

// NewSocketTracker creates a TCP state tracker.
func NewSocketTracker(dns *DNSCache) *SocketTracker {
	return &SocketTracker{
		sockets: make(map[SocketKey]*SocketState),
		dns:     dns,
	}
}

// OnStateChange is called when tcp_set_state fires (from eBPF).
// Records the state transition and timestamps.
//
// In production, this is invoked by the eBPF program that hooks
// the kernel's tcp_set_state function via kprobe.
func (st *SocketTracker) OnStateChange(key SocketKey, newState int, pid uint32, comm string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	sock, exists := st.sockets[key]
	if !exists {
		// New connection
		sock = &SocketState{
			Key:   key,
			PID:   pid,
			Comm:  comm,
			State: newState,
		}
		st.sockets[key] = sock
	} else {
		sock.State = newState
	}

	now := time.Now()
	switch newState {
	case TCP_SYN_SENT:
		sock.SYNSent = now
		log.Printf("[socket] SYN_SENT: %s (pid=%d %s)", key, pid, comm)
	case TCP_SYN_RECV:
		sock.SYNRecv = now
	case TCP_ESTABLISHED:
		sock.Established = now
		if !sock.SYNSent.IsZero() {
			sock.HandshakeDuration = sock.Established.Sub(sock.SYNSent).String()
		}
		// Resolve domain from DNS cache
		if st.dns != nil {
			sock.Domain = st.dns.ResolveDomain(key.DstIP)
		}
		log.Printf("[socket] ESTABLISHED: %s (pid=%d %s, handshake=%s, domain=%s)",
			key, pid, comm, sock.HandshakeDuration, sock.Domain)
	case TCP_CLOSE, TCP_CLOSE_WAIT:
		sock.Closed = now
		if !sock.Established.IsZero() {
			sock.ConnectionDuration = sock.Closed.Sub(sock.Established).String()
		}
		sock.StateName = "CLOSED"
		// Move to history
		st.history = append(st.history, sock)
		delete(st.sockets, key)
		log.Printf("[socket] CLOSED: %s (duration=%s)", key, sock.ConnectionDuration)
		return
	}

	sock.StateName = tcpStateName(newState)
}

// GetSocket returns the current state of a socket.
func (st *SocketTracker) GetSocket(key SocketKey) *SocketState {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.sockets[key]
}

// ActiveConnections returns all currently active connections.
func (st *SocketTracker) ActiveConnections() []*SocketState {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]*SocketState, 0, len(st.sockets))
	for _, s := range st.sockets {
		out = append(out, s)
	}
	return out
}

// CompletedConnections returns all completed connections.
func (st *SocketTracker) CompletedConnections() []*SocketState {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.history
}

// Stats returns socket tracker statistics.
func (st *SocketTracker) Stats() map[string]interface{} {
	st.mu.Lock()
	defer st.mu.Unlock()
	return map[string]interface{}{
		"active_connections":    len(st.sockets),
		"completed_connections": len(st.history),
	}
}
