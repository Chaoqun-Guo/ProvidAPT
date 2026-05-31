package grpcexport

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// CEF (Common Event Format) — Splunk / ArcSight integration
//
// CEF Format:
//   CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
//
// CEF Extension fields (key=value):
//   src — source IP
//   spt — source port
//   dst — destination IP
//   dpt — destination port
//   duser — destination user
//   filePath — file path
//   pid — process ID
//   request — URL / command
//   reason — threat description
//   cs1, cs2, cs3, cs4 — custom fields
// ═══════════════════════════════════════════════════════════════

// CEFSeverity maps internal severity to CEF (0-10).
var cefSeverity = map[string]int{
	"low":      1,
	"medium":   4,
	"high":     7,
	"critical": 10,
}

// FormatCEF converts an export event to CEF format.
//
// Output: CEF:0|ProvidAPT|ProvidAPT|2.0|1001|Suspicious File Access|7|
//   src=192.168.1.1 spt=443 dst=10.0.0.1 dpt=22 filePath=/etc/shadow
//   pid=1234 cs1Label=comm cs1=bash
func FormatCEF(evt *ExportEvent) string {
	// Determine signature ID and name based on event type
	sigID := eventToSigID(evt.EventType)
	sigName := eventToName(evt.EventType)
	sev := scoreToCEF(evt.Score)

	// Build CEF extension string
	var ext []string

	if evt.Comm != "" {
		ext = append(ext, fmt.Sprintf("cs1Label=comm cs1=%s", evt.Comm))
	}
	if evt.PID > 0 {
		ext = append(ext, fmt.Sprintf("pid=%d", evt.PID))
	}
	if evt.PPID > 0 {
		ext = append(ext, fmt.Sprintf("cs2Label=ppid cs2=%d", evt.PPID))
	}
	if evt.UID > 0 {
		ext = append(ext, fmt.Sprintf("duser=%d", evt.UID))
	}
	if evt.Pathname != "" {
		ext = append(ext, fmt.Sprintf("filePath=%s", evt.Pathname))
	}
	if evt.Daddr > 0 {
		ext = append(ext, fmt.Sprintf("dst=%s", intToIPStr(evt.Daddr)))
	}
	if evt.Dport > 0 {
		ext = append(ext, fmt.Sprintf("dpt=%d", evt.Dport))
	}
	if evt.Score > 0 {
		ext = append(ext, fmt.Sprintf("cn1Label=score cn1=%.0f", evt.Score))
	}
	if evt.IsHighRisk {
		ext = append(ext, "cs3Label=risk cs3=HIGH")
	}
	if evt.SubgraphID != "" {
		ext = append(ext, fmt.Sprintf("cs4Label=subgraph cs4=%s", evt.SubgraphID))
	}

	return fmt.Sprintf("CEF:0|ProvidAPT|ProvidAPT|2.0|%d|%s|%d|%s",
		sigID, sigName, sev, strings.Join(ext, " "))
}

// ═══════════════════════════════════════════════════════════════
// ASIM (Azure Sentinel) format
// ═══════════════════════════════════════════════════════════════

// ASIMEvent represents the Azure Sentinel Information Model schema.
type ASIMEvent struct {
	EventType     string `json:"EventType"`
	EventProduct  string `json:"EventProduct"`
	EventVendor   string `json:"EventVendor"`
	EventSchema   string `json:"EventSchemaVersion"`
	EventCount    int    `json:"EventCount"`
	TimeGenerated string `json:"TimeGenerated"`

	SrcProcName string `json:"SrcProcName,omitempty"`
	SrcProcPID  int    `json:"SrcProcPID,omitempty"`

	DstFilePath string `json:"DstFilePath,omitempty"`
	DstIPAddr   string `json:"DstIpAddr,omitempty"`
	DstPortNum  int    `json:"DstPortNumber,omitempty"`

	ThreatScore    int    `json:"ThreatScore,omitempty"`
	ThreatRisk     string `json:"ThreatRisk,omitempty"`
	SubgraphID     string `json:"SubgraphId,omitempty"`
}

// FormatASIMJSON converts an export event to ASIM-compliant JSON.
func FormatASIMJSON(evt *ExportEvent) string {
	asim := ASIMEvent{
		EventType:     eventToName(evt.EventType),
		EventProduct:  "ProvidAPT",
		EventVendor:   "ProvidAPT",
		EventSchema:   "0.1.0",
		EventCount:    1,
		TimeGenerated: time.Unix(0, evt.Timestamp).UTC().Format(time.RFC3339Nano),

		SrcProcName: evt.Comm,
		SrcProcPID:  int(evt.PID),

		DstFilePath: evt.Pathname,
		DstIPAddr:   intToIPStr(evt.Daddr),
		DstPortNum:  int(evt.Dport),

		ThreatScore: int(evt.Score),
		SubgraphID:  evt.SubgraphID,
	}
	if evt.IsHighRisk {
		asim.ThreatRisk = "High"
	}

	data, _ := json.Marshal(asim)
	return string(data)
}

// ═══════════════════════════════════════════════════════════════
// JSON CLI mode
// ═══════════════════════════════════════════════════════════════

// JSONOutput is the standard JSON output envelope for CLI tools.
type JSONOutput struct {
	Version   string        `json:"version"`
	Timestamp string        `json:"timestamp"`
	Count     int           `json:"count"`
	Events    []*ExportEvent `json:"events,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// FormatJSONCLI wraps export events in a standard JSON envelope.
func FormatJSONCLI(events []*ExportEvent, err error) string {
	out := &JSONOutput{
		Version:   "2.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Count:     len(events),
		Events:    events,
	}
	if err != nil {
		out.Error = err.Error()
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	return string(data)
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

func eventToSigID(eventType uint32) int {
	switch eventType {
	case 10:
		return 1001
	case 11, 12:
		return 1002
	case 20:
		return 2001
	case 50:
		return 3001
	case 51:
		return 3002
	default:
		return 9000
	}
}

func eventToName(eventType uint32) string {
	switch eventType {
	case 1:
		return "Process Fork"
	case 2:
		return "Process Exec"
	case 10:
		return "File Open"
	case 11:
		return "File Create"
	case 12:
		return "File Modify"
	case 20:
		return "Network Connect"
	case 21:
		return "Network Accept"
	case 50:
		return "Memory File Create"
	case 51:
		return "Memory Execute"
	default:
		return "Unknown"
	}
}

func scoreToCEF(score float64) int {
	switch {
	case score >= 50:
		return 10
	case score >= 30:
		return 7
	case score >= 10:
		return 4
	default:
		return 1
	}
}

func intToIPStr(ip uint32) string {
	if ip == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}
