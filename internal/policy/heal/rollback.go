package heal

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// Precise rollback
// ═══════════════════════════════════════════════════════════════

// RollbackResult summarizes the rollback actions taken.
type RollbackResult struct {
	ProcessesKilled  int      `json:"processes_killed"`
	FilesQuarantined int      `json:"files_quarantined"`
	SnapshotsTriggered int    `json:"snapshots_triggered"`
	Errors           []string `json:"errors,omitempty"`
	DryRun           bool     `json:"dry_run"`
}

// RollbackConfig controls rollback behaviour.
type RollbackConfig struct {
	DryRun           bool   // if true, only log actions (no execution)
	KillProcesses    bool   // kill malicious child processes
	QuarantineFiles  bool   // rename contaminated files
	UseSnapshots     bool   // trigger BTRFS/ZFS rollback
	SnapshotCmd      string // "auto", "btrfs", "zfs"
	SnapshotName     string // snapshot to roll back to
	QuarantineDir    string // move quarantined files here
}

// DefaultRollbackConfig returns a safe default (dry-run only).
func DefaultRollbackConfig() *RollbackConfig {
	return &RollbackConfig{
		DryRun:          true,
		KillProcesses:   true,
		QuarantineFiles: true,
		UseSnapshots:    false,
		SnapshotCmd:     "auto",
		QuarantineDir:   "/var/quarantine/providapt",
	}
}

// Rollback executes the rollback actions based on the impact report.
func Rollback(report *ImpactReport, cfg *RollbackConfig) *RollbackResult {
	result := &RollbackResult{DryRun: cfg.DryRun}

	if cfg.KillProcesses {
		for _, child := range report.ChildProcesses {
			if child.PID == 0 {
				continue
			}
			_ = fmt.Sprintf("kill -9 %d", child.PID)
			if cfg.DryRun {
				log.Printf("[heal] DRY-RUN: kill -9 %d (%s)", child.PID, child.Comm)
				result.ProcessesKilled++
			} else {
				if err := exec.Command("kill", "-9", fmt.Sprintf("%d", child.PID)).Run(); err != nil {
					result.Errors = append(result.Errors,
						fmt.Sprintf("kill %d: %v", child.PID, err))
				} else {
					result.ProcessesKilled++
					log.Printf("[heal] killed PID %d (%s)", child.PID, child.Comm)
				}
			}
		}
	}

	if cfg.QuarantineFiles {
		for _, file := range report.FilesWritten {
			if file.Path == "" || file.Path == "?" {
				continue
			}
			if cfg.DryRun {
				log.Printf("[heal] DRY-RUN: quarantine %s", file.Path)
				result.FilesQuarantined++
			} else {
				// Rename to .quarantine extension
				qPath := file.Path + ".quarantine"
				if err := exec.Command("mv", file.Path, qPath).Run(); err != nil {
					result.Errors = append(result.Errors,
						fmt.Sprintf("quarantine %s: %v", file.Path, err))
				} else {
					result.FilesQuarantined++
					log.Printf("[heal] quarantined %s → %s", file.Path, qPath)
				}
			}
		}
	}

	if cfg.UseSnapshots {
		n := triggerSnapshotRollback(cfg)
		result.SnapshotsTriggered = n
	}

	return result
}

// triggerSnapshotRollback initiates filesystem snapshot rollback.
func triggerSnapshotRollback(cfg *RollbackConfig) int {
	// Auto-detect filesystem
	if cfg.SnapshotCmd == "auto" {
		if cmdExists("btrfs") {
			cfg.SnapshotCmd = "btrfs"
		} else if cmdExists("zfs") {
			cfg.SnapshotCmd = "zfs"
		} else {
			log.Printf("[heal] no snapshot-capable filesystem detected")
			return 0
		}
	}

	snapName := cfg.SnapshotName
	if snapName == "" {
		snapName = "providapt-pre-incident" // default snapshot name
	}

	var cmd *exec.Cmd
	switch cfg.SnapshotCmd {
	case "btrfs":
		cmd = exec.Command("btrfs", "subvolume", "snapshot", "-r", snapName, "/")
	case "zfs":
		cmd = exec.Command("zfs", "rollback", "-r", snapName)
	default:
		return 0
	}

	if cfg.DryRun {
		log.Printf("[heal] DRY-RUN: %s", strings.Join(cmd.Args, " "))
		return 1
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[heal] snapshot rollback failed: %v\n%s", err, string(output))
		return 0
	}
	log.Printf("[heal] snapshot rollback initiated: %s", snapName)
	return 1
}

func cmdExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
