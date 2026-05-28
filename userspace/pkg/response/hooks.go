package response

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// ═══════════════════════════════════════════════════════════════
// Response hook orchestrator
// ═══════════════════════════════════════════════════════════════

// ResponseConfig controls when and how response actions are taken.
type ResponseConfig struct {
	// ThreatThreshold — minimum score to trigger response (0=disabled).
	ThreatThreshold float64

	// OutputDir — where to store dump and capture files.
	OutputDir string

	// EnableMemoryDump — set false to skip memory dumps.
	EnableMemoryDump bool

	// EnableCapture — set false to skip FD/env capture.
	EnableCapture bool

	// MaxDumpSizeMB — skip memory regions larger than this.
	MaxDumpSizeMB int
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *ResponseConfig {
	return &ResponseConfig{
		ThreatThreshold:  25.0, // HIGH severity+
		OutputDir:        "/var/log/providapt/response",
		EnableMemoryDump: true,
		EnableCapture:    true,
		MaxDumpSizeMB:    64,
	}
}

// ResponseHook is the main orchestrator.  It is called by the
// analyzer when a finding exceeds the threat threshold.
type ResponseHook struct {
	cfg     *ResponseConfig
	evmgr   *EvidenceManager
}

// New creates a response hook.
func New(cfg *ResponseConfig, store EvidenceStore) *ResponseHook {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	os.MkdirAll(cfg.OutputDir, 0700)

	return &ResponseHook{
		cfg:   cfg,
		evmgr: NewEvidenceManager(store),
	}
}

// AlertSummary is the input from the analyzer.
type AlertSummary struct {
	AlertID     string
	ThreatScore float64
	PID         int
	Comm        string
	GraphPath   string // summary of the provenance path
}

// ResponseResult summarises what was done.
type ResponseResult struct {
	AlertID     string  `json:"alert_id"`
	Triggered   bool    `json:"triggered"`
	CaseID      string  `json:"case_id,omitempty"`
	Evidence    *EvidenceRecord `json:"evidence,omitempty"`
	DumpDir     string  `json:"dump_dir,omitempty"`
	CapFile     string  `json:"cap_file,omitempty"`
	DumpHash    string  `json:"dump_hash,omitempty"`
	CaptureHash string  `json:"capture_hash,omitempty"`
}

// OnAlert is called by the analyzer when a threat is detected.
// It checks the threshold and, if exceeded, runs the full response.
func (rh *ResponseHook) OnAlert(alert *AlertSummary) *ResponseResult {
	result := &ResponseResult{
		AlertID:   alert.AlertID,
		Triggered: alert.ThreatScore >= rh.cfg.ThreatThreshold,
	}

	if !result.Triggered {
		return result
	}

	log.Printf("[response] ⚠ THRESHOLD EXCEEDED: alert=%s score=%.1f pid=%d comm=%s",
		alert.AlertID, alert.ThreatScore, alert.PID, alert.Comm)

	// Step 1: Memory dump
	var dumpHash string
	var dumpDir string
	if rh.cfg.EnableMemoryDump {
		regions, err := DumpMemory(alert.PID)
		if err != nil {
			log.Printf("[response] dump memory: %v", err)
		} else {
			dumpDir, err = SaveDump(rh.cfg.OutputDir, alert.PID, regions)
			if err != nil {
				log.Printf("[response] save dump: %v", err)
			} else {
				// Compute hash of all dumped data
				hash := sha256.New()
				for name, data := range regions {
					hash.Write([]byte(name))
					hash.Write(data)
				}
				dumpHash = hex.EncodeToString(hash.Sum(nil))
				totalSize := 0
				for _, d := range regions {
					totalSize += len(d)
				}
				log.Printf("[response] memory dump: %s (%s, hash=%s...)",
					dumpDir, FormatDumpSize(totalSize), dumpHash[:16])
			}
		}
		result.DumpDir = dumpDir
		result.DumpHash = dumpHash
	}

	// Step 2: Capture context
	var capHash string
	var capFile string
	if rh.cfg.EnableCapture {
		pc, err := CaptureContext(alert.PID)
		if err != nil {
			log.Printf("[response] capture context: %v", err)
		} else {
			capFile, err = SaveCapture(rh.cfg.OutputDir, pc)
			if err != nil {
				log.Printf("[response] save capture: %v", err)
			} else {
				data, _ := os.ReadFile(capFile)
				h := sha256.Sum256(data)
				capHash = hex.EncodeToString(h[:])
				log.Printf("[response] context capture: %s (%d vars, %d fds)",
					capFile, pc.Environment.Count, len(pc.OpenFDs))
			}
		}
		result.CapFile = capFile
		result.CaptureHash = capHash
	}

	// Step 3: Evidence locking
	evidence, err := rh.evmgr.CreateEvidence(
		alert.AlertID, alert.ThreatScore, alert.PID, alert.Comm,
		dumpHash, capHash, "", // graph hash passed separately
		alert.GraphPath, dumpDir, capFile,
	)
	if err != nil {
		log.Printf("[response] evidence create: %v", err)
	} else {
		result.CaseID = evidence.CaseID
		result.Evidence = evidence
		log.Printf("[response] evidence locked: case=%s signature=%s...",
			evidence.CaseID, evidence.Signature[:16])
	}

	return result
}

// ResponseHandler returns a function suitable for use as an analyzer callback.
func (rh *ResponseHook) ResponseHandler() func(alertID string, score float64, pid int, comm, graphPath string) {
	return func(alertID string, score float64, pid int, comm, graphPath string) {
		rh.OnAlert(&AlertSummary{
			AlertID:     alertID,
			ThreatScore: score,
			PID:         pid,
			Comm:        comm,
			GraphPath:   graphPath,
		})
	}
}
