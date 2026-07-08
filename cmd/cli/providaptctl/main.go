// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/diagnose"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/purge"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/releasecheck"
)

const (
	pidFile  = "/var/run/providaptd.pid"
	progName = "providaptd"
)

func usage() {
	fmt.Fprint(os.Stderr, `SYNOPSIS
    providaptctl [OPTIONS]

DESCRIPTION
    Control the ProvidAPT provenance monitor daemon.  Query status,
    stop, or restart the daemon process.  Collect diagnostic bundles
    or purge stored data.

OPTIONS
`)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
EXAMPLES
    providaptctl -status
        Show daemon status (PID, state, uptime, config path).

    providaptctl -status -json
        Show daemon status as JSON (for programmatic use).

    providaptctl -stop
        Gracefully stop the daemon (SIGTERM, 10 s timeout).

    providaptctl -restart
        Stop then start the daemon.

    providaptctl -diagnose
        Collect diagnostic bundle (kernel, probes, logs, resources)
        and create a tar.gz archive.

    providaptctl -purge -purge-mode=time -purge-cutoff=2026-01-01T00:00:00Z
        Purge data older than the cutoff time.

    providaptctl -purge -purge-mode=capacity -purge-maxbytes=104857600
        Purge oldest data until store is under 100 MB.

    providaptctl -purge -purge-mode=compliance -purge-dry-run
        Preview a full compliance wipe.

    providaptctl -config /custom/path/providapt.toml -status
        Check status with a non-default config path.

    providaptctl -release-check -config /etc/providapt/providapt.toml
        Run commercial release readiness checks for handoff.

    providaptctl -release-check -release-check-out release-readiness.md
        Write a Markdown or JSON release readiness evidence report.

    providaptctl -release-check -release-waivers release-waivers.json
        Apply reviewed warning waivers during commercial readiness checks.

    providaptctl -release-check -release-checksums dist/checksums.txt
        Validate release artifact checksum manifest format.

    providaptctl -release-check -release-checksums-signature dist/checksums.txt.sig
        Validate release checksum detached signature evidence.

    providaptctl -release-check -release-sbom dist/sbom.spdx.json,dist/sbom.cdx.json
        Validate SPDX or CycloneDX SBOM evidence files.
`)
}

func main() {
	var (
		status           = flag.Bool("status", false, "Query daemon status")
		stop             = flag.Bool("stop", false, "Stop the daemon")
		restart          = flag.Bool("restart", false, "Restart the daemon")
		cfgPath          = flag.String("config", "/etc/providapt/providapt.toml", "Config file path")
		jsonOut          = flag.Bool("json", false, "Output in JSON format")
		diagnose         = flag.Bool("diagnose", false, "Collect diagnostic bundle")
		diagnoseOut      = flag.String("diagnose-out", "/var/log/providapt", "Diagnostic bundle output directory")
		audit            = flag.Bool("audit", false, "Query audit log")
		auditCat         = flag.String("audit-cat", "all", "Audit category: security, admin, system, integrity, all")
		auditSince       = flag.String("audit-since", "", "Show entries since duration (e.g. 24h, 7d)")
		auditLimit       = flag.Int("audit-limit", 50, "Max audit entries to show")
		reload           = flag.Bool("reload", false, "Trigger config reload via daemon API")
		report           = flag.Bool("report", false, "Generate MITRE ATT&CK heatmap report")
		reportOut        = flag.String("report-out", "", "Report output path")
		dashboard        = flag.Bool("dashboard", false, "Live terminal dashboard (real-time monitoring)")
		bpf              = flag.Bool("bpf", false, "Inspect eBPF state (capabilities, programs, pinned maps)")
		verify           = flag.Bool("verify", false, "Verify store consistency")
		verifyRepair     = flag.Bool("repair", false, "Repair fixable issues (used with -verify)")
		purge            = flag.Bool("purge", false, "Purge stored data")
		purgeMode        = flag.String("purge-mode", "time", "Purge mode: time, capacity, compliance")
		purgeCutoff      = flag.String("purge-cutoff", "", "Purge cutoff time (RFC3339, e.g. 2026-01-01T00:00:00Z)")
		purgeMax         = flag.Int64("purge-maxbytes", 0, "Target remaining bytes for capacity mode")
		purgeDryRun      = flag.Bool("purge-dry-run", false, "Preview purge without deleting")
		replay           = flag.Bool("replay", false, "Replay events from NDJSON logs")
		replayInput      = flag.String("replay-input", "", "Input directory with NDJSON files (default: output dir)")
		replayMax        = flag.Int("replay-max", 0, "Max events to replay (0 = unlimited)")
		archive          = flag.Bool("archive", false, "Archive old event logs")
		archiveDir       = flag.String("archive-dir", "", "Input directory with NDJSON files (default: output dir)")
		archiveAge       = flag.Int("archive-age", 7, "Archive files older than N days")
		archiveDryRun    = flag.Bool("archive-dry-run", false, "Preview archive without archiving")
		genrules         = flag.Bool("genrules", false, "Generate Prometheus alert rules")
		genrulesOut      = flag.String("genrules-out", "", "Output path for rules file")
		profileFlag      = flag.Bool("profile", false, "Collect performance profile")
		backupFlag       = flag.Bool("backup", false, "Backup store to tar.gz archive")
		backupOut        = flag.String("backup-out", "", "Backup output path (.tar.gz)")
		restoreFlag      = flag.Bool("restore", false, "Restore store from tar.gz backup")
		restoreIn        = flag.String("restore-in", "", "Backup input path (.tar.gz)")
		configCheck      = flag.Bool("config-check", false, "Validate config file and exit")
		releaseCheck     = flag.Bool("release-check", false, "Run commercial release readiness checks")
		evidencePath     = flag.String("release-evidence", "docs/project/release-evidence-v1.2.2.md", "Release evidence file path")
		waiverPath       = flag.String("release-waivers", "", "Release warning waiver JSON file")
		checksumsPath    = flag.String("release-checksums", "", "Release artifact checksums file")
		checksumsSigPath = flag.String("release-checksums-signature", "", "Release checksums detached signature file")
		sbomPaths        = flag.String("release-sbom", "", "Release SBOM JSON file(s), separated by comma or semicolon")
		releaseOut       = flag.String("release-check-out", "", "Write release check report (.md or .json)")
	)
	flag.Usage = usage
	flag.Parse()

	clioutput.Init(*jsonOut)

	hasAction := *status || *stop || *restart || *reload || *report || *dashboard || *diagnose || *bpf || *verify || *purge || *audit || *replay || *archive || *genrules || *profileFlag || *backupFlag || *restoreFlag || *configCheck || *releaseCheck
	if !hasAction {
		flag.Usage()
		os.Exit(1)
	}

	clioutput.PrintBanner(version.Version)

	switch {
	case *status:
		cmdStatus(*cfgPath)
	case *stop:
		cmdStop(*cfgPath)
	case *restart:
		cmdRestart(*cfgPath)
	case *reload:
		cmdReload(*cfgPath)
	case *report:
		outDir := resolveOutputDir(*cfgPath)
		cmdReport(outDir, *reportOut)
	case *dashboard:
		cmdDashboard(*cfgPath)
	case *audit:
		cmdAudit(*cfgPath, *auditCat, *auditSince, *auditLimit)
		os.Exit(0)
	case *bpf:
		cmdBPF(*jsonOut)
	case *verify:
		cmdVerify(*cfgPath, *verifyRepair, true)
		os.Exit(0)
	case *diagnose:
		cmdDiagnose(*diagnoseOut)
	case *purge:
		cmdPurge(*cfgPath, *purgeMode, *purgeCutoff, *purgeMax, *purgeDryRun)
	case *replay:
		cmdReplay(*cfgPath, *replayInput, *replayMax)
	case *archive:
		cmdArchive(*cfgPath, *archiveDir, *archiveAge, *archiveDryRun)
	case *genrules:
		cmdGenRules(*genrulesOut)
	case *profileFlag:
		cmdProfile(*jsonOut)
	case *configCheck:
		cmdConfigCheck(*cfgPath)
		os.Exit(0)
	case *releaseCheck:
		os.Exit(cmdReleaseCheck(*cfgPath, *evidencePath, *waiverPath, *checksumsPath, *checksumsSigPath, splitReleasePaths(*sbomPaths), *releaseOut))
	case *backupFlag:
		cmdBackup(*cfgPath, *backupOut)
		os.Exit(0)
	case *restoreFlag:
		cmdRestore(*cfgPath, *restoreIn)
		os.Exit(0)
	}
}

func readPID() (int, error) {
	data, err := ioutil.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func isRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func findDaemonPID() int {
	if pid, err := readPID(); err == nil && isRunning(pid) {
		return pid
	}
	cmd := exec.Command("pgrep", "-x", progName)
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0
	}
	return pid
}

type statusInfo struct {
	Running    bool   `json:"running"`
	PID        int    `json:"pid,omitempty"`
	State      string `json:"state,omitempty"`
	Comm       string `json:"comm,omitempty"`
	ConfigPath string `json:"config_path"`
	ConfigOK   bool   `json:"config_ok"`
	Pidfile    string `json:"pidfile,omitempty"`
}

func cmdStatus(cfgPath string) {
	pid := findDaemonPID()
	if pid == 0 {
		if clioutput.IsJSONMode() {
			clioutput.PrintJSON(statusInfo{Running: false, ConfigPath: cfgPath})
		} else {
			fmt.Println(clioutput.Warnf("ProvidAPT: stopped"))
		}
		os.Exit(1)
	}

	info := statusInfo{
		Running:    true,
		PID:        pid,
		ConfigPath: cfgPath,
	}

	if _, err := os.Stat(cfgPath); err == nil {
		info.ConfigOK = true
	}

	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	if data, err := ioutil.ReadFile(statPath); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 22 {
			info.Comm = strings.Trim(fields[1], "()")
			info.State = fields[2]
		}
	}

	if _, err := os.Stat(pidFile); err == nil {
		info.Pidfile = pidFile
	}

	if clioutput.IsJSONMode() {
		clioutput.PrintJSON(info)
		return
	}

	fmt.Println(clioutput.Okf("ProvidAPT: running"))

	t := clioutput.NewTable("Field", "Value")
	t.AddRow("PID", strconv.Itoa(info.PID))
	t.AddRow("State", info.State)
	t.AddRow("Process", info.Comm)
	if info.ConfigOK {
		t.AddRow("Config", clioutput.Okf("%s", info.ConfigPath))
	} else {
		t.AddRow("Config", clioutput.Warnf("%s (not found)", info.ConfigPath))
	}
	if info.Pidfile != "" {
		t.AddRow("PID file", info.Pidfile)
	}
	t.Render()
}

func cmdStop(cfgPath string) {
	pid := findDaemonPID()
	if pid == 0 {
		clioutput.Printf("%s\n", clioutput.Warnf("ProvidAPT: not running"))
		return
	}

	clioutput.Printf("%s\n", clioutput.Infof("Stopping ProvidAPT (PID %d)...", pid))
	proc, err := os.FindProcess(pid)
	if err != nil {
		clioutput.Fatalf("Error finding process: %v", err)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		clioutput.Fatalf("Error sending SIGTERM: %v", err)
	}

	done := make(chan struct{})
	go func() {
		proc.Wait()
		close(done)
	}()

	select {
	case <-done:
		clioutput.Printf("%s\n", clioutput.Okf("ProvidAPT: stopped"))
	case <-time.After(10 * time.Second):
		clioutput.Printf("%s\n", clioutput.Warnf("ProvidAPT: force killing..."))
		proc.Kill()
		<-done
		clioutput.Printf("%s\n", clioutput.Errf("ProvidAPT: killed"))
	}

	os.Remove(pidFile)

	if as := auditStore(cfgPath); as != nil {
		as.Log(audit.Entry{
			Category: audit.CatAdmin,
			Severity: "INFO",
			Message:  "Daemon stopped",
			Source:   "cli",
		})
		as.Close()
	}
}

func cmdRestart(cfgPath string) {
	cmdStop(cfgPath)
	clioutput.Printf("%s\n", clioutput.Infof("Starting ProvidAPT..."))
	cmd := exec.Command(progName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		clioutput.Fatalf("Error starting %s: %v", progName, err)
	}
	clioutput.Printf("%s\n", clioutput.Okf("ProvidAPT: started (PID %d)", cmd.Process.Pid))

	if as := auditStore(cfgPath); as != nil {
		as.Log(audit.Entry{
			Category: audit.CatAdmin,
			Severity: "INFO",
			Message:  "Daemon restarted",
			Source:   "cli",
		})
		as.Close()
	}
}

// cmdReload triggers a config reload by sending POST to the daemon API.
func cmdReload(cfgPath string) {
	clioutput.Printf("%s\n", clioutput.Infof("Reloading daemon configuration..."))

	cfg, err := config.Load(cfgPath)
	if err != nil {
		clioutput.Fatalf("Config load failed: %v", err)
	}

	apiAddr := cfg.API.REST
	if apiAddr == "" {
		apiAddr = "http://127.0.0.1:8080"
	} else if !strings.HasPrefix(apiAddr, "http") {
		apiAddr = "http://" + apiAddr
	}

	url := apiAddr + "/api/v1/admin/reload"
	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		clioutput.Fatalf("Reload request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotImplemented {
		clioutput.Printf("%s\n", clioutput.Okf("Config reload triggered"))
	} else {
		clioutput.Printf("%s\n", clioutput.Warnf("Reload returned %d", resp.StatusCode))
	}

	if as := auditStore(cfgPath); as != nil {
		as.Log(audit.Entry{
			Category: audit.CatAdmin,
			Severity: "INFO",
			Message:  "Config reload triggered",
			Source:   "cli",
		})
		as.Close()
	}
}

func cmdDiagnose(outDir string) {
	clioutput.Printf("%s\n", clioutput.Infof("Collecting diagnostic bundle..."))

	path, err := diagnose.Collect(outDir)
	if err != nil {
		clioutput.Fatalf("Diagnostic collection failed: %v", err)
	}

	// Get file size
	fi, err := os.Stat(path)
	size := "unknown"
	if err == nil {
		size = formatBytes(fi.Size())
	}

	clioutput.Printf("%s\n", clioutput.Okf("Diagnostic bundle created"))
	t := clioutput.NewTable("Field", "Value")
	t.AddRow("Path", path)
	t.AddRow("Size", size)
	t.Render()
}

func cmdReleaseCheck(cfgPath, evidencePath, waiverPath, checksumsPath, checksumsSigPath string, sbomPaths []string, reportPath string) int {
	report := releasecheck.Run(releasecheck.Options{
		ConfigPath:             cfgPath,
		EvidencePath:           evidencePath,
		WaiverPath:             waiverPath,
		ChecksumsPath:          checksumsPath,
		ChecksumsSignaturePath: checksumsSigPath,
		SBOMPaths:              sbomPaths,
		Version:                version.Version,
		Commit:                 version.Commit,
		BuildDate:              version.Date,
	})

	if err := releasecheck.WriteReport(reportPath, report); err != nil {
		if clioutput.IsJSONMode() {
			clioutput.PrintJSON(map[string]string{"error": err.Error()})
		} else {
			clioutput.Printf("%s\n", clioutput.Errf("Failed to write release report: %v", err))
		}
		return 2
	}

	if clioutput.IsJSONMode() {
		clioutput.PrintJSON(report)
		if report.HasFailures() {
			return 2
		}
		return 0
	}

	clioutput.Printf("%s\n", clioutput.Infof("Release readiness: %s", report.Summary()))
	table := clioutput.NewTable("Status", "Check", "Detail")
	for _, check := range report.Checks {
		status := check.Status
		switch check.Status {
		case releasecheck.StatusPass:
			status = clioutput.Okf("PASS")
		case releasecheck.StatusWarn:
			status = clioutput.Warnf("WARN")
		case releasecheck.StatusWaived:
			status = clioutput.Warnf("WAIVED")
		case releasecheck.StatusFail:
			status = clioutput.Errf("FAIL")
		}
		detail := check.Message
		if check.FixSuggestion != "" {
			detail += " | fix: " + check.FixSuggestion
		}
		if check.Waiver != nil {
			detail += fmt.Sprintf(" | waiver: approved by %s, reason: %s", check.Waiver.ApprovedBy, check.Waiver.Reason)
			if check.Waiver.Expires != "" {
				detail += ", expires: " + check.Waiver.Expires
			}
		}
		table.AddRow(status, check.Name, detail)
	}
	table.Render()

	if report.CommercialReady {
		clioutput.Printf("%s\n", clioutput.Okf("Commercial release checks passed"))
	} else if report.ReleaseReady {
		clioutput.Printf("%s\n", clioutput.Warnf("Release checks passed with commercial warnings"))
	} else {
		clioutput.Printf("%s\n", clioutput.Errf("Release checks failed"))
		return 2
	}
	if reportPath != "" {
		clioutput.Printf("%s\n", clioutput.Okf("Release check report written: %s", reportPath))
	}
	return 0
}

func splitReleasePaths(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';'
	})
	paths := make([]string, 0, len(fields))
	for _, field := range fields {
		if path := strings.TrimSpace(field); path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func cmdPurge(cfgPath, mode, cutoff string, maxBytes int64, dryRun bool) {
	// Stop the daemon first
	cmdStop(cfgPath)

	// Load config for store path
	cfg, err := config.Load(cfgPath)
	if err != nil {
		clioutput.Fatalf("Config load failed: %v", err)
	}

	storePath := cfg.Output.Dir + "/store"
	if storePath == "/store" {
		storePath = "/var/log/providapt/store"
	}

	// Parse purge mode
	var purgeMode purge.PurgeMode
	switch mode {
	case "time":
		purgeMode = purge.PurgeByTime
	case "capacity":
		purgeMode = purge.PurgeByCapacity
	case "compliance":
		purgeMode = purge.PurgeCompliance
	default:
		clioutput.Fatalf("Unknown purge mode: %s (use: time, capacity, compliance)", mode)
	}

	// Build config
	purgeCfg := &purge.PurgeConfig{
		Mode:      purgeMode,
		StorePath: storePath,
		DryRun:    dryRun,
	}

	if purgeMode == purge.PurgeByTime {
		if cutoff == "" {
			clioutput.Fatalf("-purge-cutoff required for time mode (RFC3339 format)")
		}
		t, err := time.Parse(time.RFC3339, cutoff)
		if err != nil {
			clioutput.Fatalf("Invalid cutoff time %q: %v", cutoff, err)
		}
		purgeCfg.Cutoff = t
	}

	if purgeMode == purge.PurgeByCapacity {
		if maxBytes <= 0 {
			clioutput.Fatalf("-purge-maxbytes required for capacity mode")
		}
		purgeCfg.MaxBytes = maxBytes
	}

	// Load encryption key if configured
	if cfg.Storage.Encrypt && cfg.Storage.KeyFile != "" {
		data, err := os.ReadFile(cfg.Storage.KeyFile)
		if err != nil {
			clioutput.Fatalf("Failed to read encryption key: %v", err)
		}
		purgeCfg.EncKey = data
	}

	clioutput.Printf("%s\n", clioutput.Infof("Purging data (mode=%s, dry_run=%v)...", mode, dryRun))

	report, err := purge.Execute(purgeCfg)
	if err != nil {
		clioutput.Fatalf("Purge failed: %v", err)
	}

	clioutput.Printf("%s\n", clioutput.Okf("Purge complete"))

	if as := auditStore(cfgPath); as != nil {
		as.Log(audit.Entry{
			Category: audit.CatAdmin,
			Severity: "INFO",
			Message:  "Data purge executed",
			Source:   "cli",
			Details: map[string]interface{}{
				"mode":            mode,
				"dry_run":         dryRun,
				"total_deleted":   report.TotalKeysDeleted,
				"bytes_freed":     report.BytesFreed,
				"remaining_bytes": report.RemainingSize,
			},
		})
		as.Close()
	}

	t := clioutput.NewTable("Field", "Value")
	t.AddRow("Mode", report.Mode)
	t.AddRow("Nodes Deleted", fmt.Sprintf("%d", report.NodesDeleted))
	t.AddRow("Edges Deleted", fmt.Sprintf("%d", report.EdgesDeleted))
	t.AddRow("Total Keys Deleted", fmt.Sprintf("%d", report.TotalKeysDeleted))
	t.AddRow("Bytes Freed", formatBytes(report.BytesFreed))
	t.AddRow("Remaining Size", formatBytes(report.RemainingSize))
	t.AddRow("Duration", report.Duration.Round(time.Millisecond).String())
	if report.DryRun {
		t.AddRow("Dry Run", "true (no data was deleted)")
	}
	t.Render()

	// Restart the daemon
	clioutput.Printf("%s\n", clioutput.Infof("Restarting daemon..."))
	cmd := exec.Command(progName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		clioutput.Warnf("Failed to restart daemon: %v", err)
	} else {
		clioutput.Printf("%s\n", clioutput.Okf("Daemon restarted (PID %d)", cmd.Process.Pid))
	}
}

// auditStore opens the audit store from a config path, or returns nil on error.
func auditStore(cfgPath string) *audit.Store {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil
	}
	dir := cfg.Output.Dir
	if dir == "" {
		dir = "/var/log/providapt"
	}
	s, err := audit.New(dir)
	if err != nil {
		return nil
	}
	return s
}

// formatBytes returns a human-readable byte size string.
func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	}
	if b < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
}
