// Package export implements the gRPC-based telemetry export and
// cross-host correlation for ProvidAPT.
//
// Architecture:
//
//   Local Agent (export client)                 Central Server
//   ┌──────────────────────────┐    gRPC    ┌──────────────────────┐
//   │ ReportSocketEvent(stream)│──────────▶│ Server.Receive()      │
//   │ ReportNode(stream)       │           │   → Stitch()          │
//   │ ReportEdge(stream)       │           │   → Global Graph      │
//   └──────────────────────────┘           └──────────────────────┘
package export

import (
	"fmt"
)

// ═══════════════════════════════════════════════════════════════
// Protocol models (mirrors what protobuf would generate)
// ═══════════════════════════════════════════════════════════════

// SocketEvent is the core telemetry unit for network connections.
type SocketEvent struct {
	AgentID    string `json:"agent_id"`
	Hostname   string `json:"hostname"`
	Timestamp  int64  `json:"timestamp_ns"` // UnixNano

	// Process identity
	PID  uint32 `json:"pid"`
	Comm string `json:"comm"`
	UID  uint32 `json:"uid"`

	// 5-tuple
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint32 `json:"src_port"`
	DstPort  uint32 `json:"dst_port"`
	Protocol uint32 `json:"protocol"` // 6=TCP, 17=UDP

	// TCP fingerprint
	SeqHash     uint32 `json:"seq_hash"`     // FNV-1a of snd_nxt
	TCPOptions  uint32 `json:"tcp_options"`  // bitmap of options
	WindowSize  uint32 `json:"window_size,omitempty"`

	// Connection state
	ConnStatus string `json:"conn_status"` // SYN_SENT, ESTABLISHED, CLOSE
}

// SocketKey returns a compact identifier for correlation.
func (s *SocketEvent) SocketKey() string {
	return fmt.Sprintf("%s:%d-%s:%d-%d",
		s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, s.Protocol)
}

// SeqHashKey includes the sequence hash for precise matching.
func (s *SocketEvent) SeqHashKey() string {
	return fmt.Sprintf("%s|%d", s.SocketKey(), s.SeqHash)
}

// ═══════════════════════════════════════════════════════════════
// ProvenanceNode / Edge — minimal cross-host graph elements
// ═══════════════════════════════════════════════════════════════

type ProvenanceNode struct {
	AgentID   string `json:"agent_id"`
	NodeID    string `json:"node_id"`
	Label     string `json:"label"`
	NodeType  string `json:"node_type"` // process, file, network
	Timestamp int64  `json:"timestamp_ns"`
}

type ProvenanceEdge struct {
	AgentID   string `json:"agent_id"`
	EdgeID    string `json:"edge_id"`
	Source    string `json:"source"`
	Target    string `json:"target"`
	Relation  string `json:"relation"`
	Timestamp int64  `json:"timestamp_ns"`
}

// ═══════════════════════════════════════════════════════════════
// CrossHostEdge — stitched edge between machines
// ═══════════════════════════════════════════════════════════════

type CrossHostEdge struct {
	SourceAgent string `json:"source_agent"`
	SourceNode  string `json:"source_node"`
	SourcePID   uint32 `json:"source_pid"`

	TargetAgent string `json:"target_agent"`
	TargetNode  string `json:"target_node"`
	TargetPID   uint32 `json:"target_pid"`

	SocketKey   string `json:"socket_key"`
	SeqHash     uint32 `json:"seq_hash"`
	Timestamp   int64  `json:"timestamp_ns"`

	Confidence  float64 `json:"confidence"` // 0.0–1.0
}

// ─── Report / Ack ──────────────────────────────────────────

type ReportAck struct {
	Received   int    `json:"received"`
	Status     string `json:"status"`
}
