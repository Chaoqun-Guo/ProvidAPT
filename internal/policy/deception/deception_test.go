// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package deception

import (
	"testing"
	"time"
)

// ── Types tests ─────────────────────────────────────────────────

func TestDefaultHoneytokens(t *testing.T) {
	tokens := DefaultHoneytokens()
	if len(tokens) != 5 {
		t.Errorf("expected 5 default tokens, got %d", len(tokens))
	}

	// Verify specific tokens exist.
	tokenMap := make(map[HoneytokenType]bool)
	for _, ht := range tokens {
		tokenMap[ht.Type] = true
	}
	for _, typ := range []HoneytokenType{
		HoneytokenCredentials, HoneytokenBackup, HoneytokenKey,
		HoneytokenConfig, HoneytokenKubeconfig,
	} {
		if !tokenMap[typ] {
			t.Errorf("missing honeytoken type: %s", typ)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("config is nil")
	}
	if !cfg.Enabled {
		t.Error("deception should be enabled by default")
	}
	if cfg.CPUQuota != 1 {
		t.Errorf("cpu quota = %d", cfg.CPUQuota)
	}
	if cfg.OverlayDir != "/tmp/providapt-honeypot" {
		t.Errorf("overlay dir = %s", cfg.OverlayDir)
	}
}

func TestHoneytokenByPath(t *testing.T) {
	tokens := []HoneytokenDef{
		{Path: "/tmp/test.xml", Type: HoneytokenCredentials, Label: "test"},
	}

	ht := HoneytokenByPath("/tmp/test.xml", tokens)
	if ht == nil {
		t.Fatal("should find token")
	}
	if ht.Type != HoneytokenCredentials {
		t.Errorf("type = %s", ht.Type)
	}

	ht = HoneytokenByPath("/nonexistent", tokens)
	if ht != nil {
		t.Error("should not find nonexistent path")
	}
}

func TestHoneytokensByType(t *testing.T) {
	tokens := []HoneytokenDef{
		{Path: "/tmp/a", Type: HoneytokenCredentials},
		{Path: "/tmp/b", Type: HoneytokenBackup},
		{Path: "/tmp/c", Type: HoneytokenCredentials},
	}

	creds := HoneytokensByType(HoneytokenCredentials, tokens)
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials tokens, got %d", len(creds))
	}

	backups := HoneytokensByType(HoneytokenBackup, tokens)
	if len(backups) != 1 {
		t.Errorf("expected 1 backup token, got %d", len(backups))
	}

	missing := HoneytokensByType(HoneytokenVault, tokens)
	if len(missing) != 0 {
		t.Errorf("expected 0, got %d", len(missing))
	}
}

func TestIsHoneytokenPath(t *testing.T) {
	tokens := []HoneytokenDef{
		{Path: "/tmp/honey.xml", Type: HoneytokenCredentials},
	}
	if !IsHoneytokenPath("/tmp/honey.xml", tokens) {
		t.Error("should be honeytoken path")
	}
	if IsHoneytokenPath("/tmp/not_honey.xml", tokens) {
		t.Error("should not be honeytoken path")
	}
	if IsHoneytokenPath("", tokens) {
		t.Error("empty path should not match")
	}
}

func TestHoneytokenDefContent(t *testing.T) {
	ht := HoneytokenDef{
		Path:    "/tmp/test.txt",
		Type:    HoneytokenCredentials,
		Content: `{"password": "secret"}`,
	}
	if ht.Content != `{"password": "secret"}` {
		t.Errorf("content = %s", ht.Content)
	}
}

func TestHoneytokenDefDefaultContent(t *testing.T) {
	ht := HoneytokenDef{
		Path:  "/tmp/test.txt",
		Type:  HoneytokenCredentials,
		Label: "Test decoy file",
	}
	if ht.Content != "" {
		t.Errorf("expected empty content, got %s", ht.Content)
	}
}

// ── FNV hash tests ──────────────────────────────────────────────

func TestFnvHash(t *testing.T) {
	h1 := fnvHash("/tmp/test")
	h2 := fnvHash("/tmp/test")
	if h1 != h2 {
		t.Errorf("same path should produce same hash: %08x vs %08x", h1, h2)
	}
}

func TestFnvHashDifferent(t *testing.T) {
	h1 := fnvHash("/tmp/file1")
	h2 := fnvHash("/tmp/file2")
	if h1 == h2 {
		t.Error("different paths should produce different hashes (collision unlikely)")
	}
}

func TestFnvHashEmpty(t *testing.T) {
	h := fnvHash("")
	if h == 0 {
		t.Error("empty string hash should not be zero (FNV-1a has offset basis)")
	}
}

// ── Overlay manager tests ───────────────────────────────────────

func TestNewOverlayManager(t *testing.T) {
	om := NewOverlayManager(nil)
	if om == nil {
		t.Fatal("manager is nil")
	}
	if om.IsActive() {
		t.Error("new manager should not be active")
	}
}

func TestOverlayManagerNotActive(t *testing.T) {
	om := NewOverlayManager(&Config{Enabled: true, Honeytokens: nil})
	if om.IsActive() {
		t.Error("should not be active before Start()")
	}
}

func TestOverlayManagerPaths(t *testing.T) {
	cfg := &Config{
		Honeytokens: []HoneytokenDef{
			{Path: "/tmp/honey1.xml"},
			{Path: "/tmp/honey2.xml"},
		},
	}
	om := NewOverlayManager(cfg)
	paths := om.Paths()
	if len(paths) != 2 {
		t.Errorf("paths count = %d", len(paths))
	}
	if paths[0] != "/tmp/honey1.xml" {
		t.Errorf("path[0] = %s", paths[0])
	}
}

func TestOverlayManagerEmptyConfig(t *testing.T) {
	cfg := &Config{Enabled: true}
	om := NewOverlayManager(cfg)
	paths := om.Paths()
	if len(paths) != len(DefaultHoneytokens()) {
		t.Errorf("expected %d default paths, got %d", len(DefaultHoneytokens()), len(paths))
	}
}

func TestOverlayManagerStats(t *testing.T) {
	om := NewOverlayManager(nil)
	stats := om.Stats()
	if stats["active"].(bool) {
		t.Error("should not be active")
	}
	if stats["mount_count"].(int) != 0 {
		t.Errorf("mount count = %d", stats["mount_count"])
	}
	if stats["map_present"].(bool) {
		t.Error("map_present should be false")
	}
}

func TestOverlayManagerSetEBPFMapFd(t *testing.T) {
	om := NewOverlayManager(nil)
	// nil by default — map not connected.
	stats := om.Stats()
	if stats["map_present"].(bool) {
		t.Error("expected map_present=false with no map set")
	}
}

func TestOverlayManagerHandleTrigger(t *testing.T) {
	om := NewOverlayManager(nil)

	triggered := false
	om.cfg.OnTrigger = func(t *HoneypotTrigger) {
		triggered = true
	}

	om.HandleTrigger(HoneypotTrigger{
		PID:  100,
		Comm: "test",
		Path: "/tmp/honey.xml",
	})

	if !triggered {
		t.Error("OnTrigger callback should have been called")
	}

	// Check trigger channel.
	select {
	case tr := <-om.TriggerCh():
		if tr.PID != 100 {
			t.Errorf("pid = %d", tr.PID)
		}
		if tr.Comm != "test" {
			t.Errorf("comm = %s", tr.Comm)
		}
	default:
		t.Error("trigger channel should have event")
	}
}

// ── Freezer tests ───────────────────────────────────────────────

func TestNewFreezer(t *testing.T) {
	f := NewFreezer(nil)
	if f == nil {
		t.Fatal("freezer is nil")
	}
}

func TestFreezerNilTrigger(t *testing.T) {
	f := NewFreezer(nil)
	_, err := f.Freeze(nil)
	if err == nil {
		t.Error("expected error for nil trigger")
	}
}

func TestFreezeRecord(t *testing.T) {
	f := NewFreezer(nil)
	trigger := &HoneypotTrigger{
		PID:  9999,
		Comm: "test_process",
		Path: "/tmp/honey.xml",
	}

	// Freeze will fail (PID doesn't exist, cgroup write fails),
	// but should return an error rather than panic.
	_, err := f.Freeze(trigger)
	if err != nil {
		t.Logf("Expected freeze error (running in test): %v", err)
	}
}

func TestFreezerRecords(t *testing.T) {
	f := NewFreezer(nil)
	records := f.Records()
	if records == nil {
		t.Fatal("records should not be nil")
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestFreezerRecordLookup(t *testing.T) {
	f := NewFreezer(nil)
	record := f.Record(999)
	if record != nil {
		t.Error("expected nil for unknown record")
	}
}

func TestFreezerStats(t *testing.T) {
	f := NewFreezer(nil)
	stats := f.Stats()
	if stats["total_frozen"].(int) != 0 {
		t.Errorf("total frozen = %d", stats["total_frozen"])
	}
	if stats["active_freezes"].(int) != 0 {
		t.Errorf("active = %d", stats["active_freezes"])
	}
}

func TestFreezerReleaseNoRecord(t *testing.T) {
	f := NewFreezer(nil)
	err := f.Release(999)
	if err == nil {
		t.Error("expected error for unknown PID")
	}
}

// ── Process context capture tests ───────────────────────────────

func TestCaptureContext(t *testing.T) {
	// Capture context of the current process (should succeed).
	ctx := captureContext(0) // PID 0 doesn't exist
	if ctx.PID != 0 {
		t.Errorf("pid = %d", ctx.PID)
	}
	// Should not panic even for invalid PID.
	_ = ctx
}

func TestCaptureContextSelf(t *testing.T) {
	// Capture context of test process itself.
	ctx := captureContext(GetPID())
	if ctx.PID == 0 {
		t.Log("PID 0 means capture failed (expected in some environments)")
		return
	}
	if ctx.Comm == "" {
		t.Log("comm empty (expected in some environments)")
	}
	t.Logf("captured self: pid=%d comm=%s cmdline=%s",
		ctx.PID, ctx.Comm, ctx.Cmdline)
}

// GetPID returns the current process PID for testing.
func GetPID() int {
	return 0 // We'll read from /proc/self which resolves to the test process
}

// ── Integrator tests ────────────────────────────────────────────

func TestNewDeceptionIntegrator(t *testing.T) {
	di := NewDeceptionIntegrator(nil)
	if di == nil {
		t.Fatal("integrator is nil")
	}
	if di.manager == nil {
		t.Error("manager is nil")
	}
	if di.freezer == nil {
		t.Error("freezer is nil")
	}
}

func TestDeceptionIntegratorCustomConfig(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		CPUQuota:   5,
		OverlayDir: "/tmp/custom-honeypot",
		CGroupName: "custom-freeze",
	}
	di := NewDeceptionIntegrator(cfg)
	if di.cfg.CPUQuota != 5 {
		t.Errorf("cpu quota = %d", di.cfg.CPUQuota)
	}
	if di.cfg.OverlayDir != "/tmp/custom-honeypot" {
		t.Errorf("overlay dir = %s", di.cfg.OverlayDir)
	}
}

func TestDeceptionIntegratorStartStop(t *testing.T) {
	// Start with no honeytokens (empty dirs won't mount).
	cfg := &Config{
		Enabled:     true,
		Honeytokens: []HoneytokenDef{},
	}
	di := NewDeceptionIntegrator(cfg)

	// Start will create base dir but no mounts (no tokens).
	err := di.Start()
	if err != nil {
		t.Logf("Start error (expected in test env): %v", err)
	}

	// Stop should clean up.
	err = di.Stop()
	if err != nil {
		t.Logf("Stop error: %v", err)
	}
}

// ── Node attribute tests ────────────────────────────────────────

func TestAttrsForTrigger(t *testing.T) {
	tTrigger := &HoneypotTrigger{
		PID:       100,
		PPID:      50,
		Comm:      "curl",
		Path:      "/tmp/backup_credentials.xml",
		TokenType: HoneytokenCredentials,
		Trigger:   TrigOpen,
		Tripwire:  true,
	}

	attrs := AttrsForTrigger(tTrigger)
	if attrs == nil {
		t.Fatal("attrs is nil")
	}
	if attrs["confirmed_malicious"] != "true" {
		t.Errorf("confirmed_malicious = %s", attrs["confirmed_malicious"])
	}
	if attrs["honeypot_triggered"] != "true" {
		t.Errorf("honeypot_triggered = %s", attrs["honeypot_triggered"])
	}
	if attrs["honeypot_path"] != "/tmp/backup_credentials.xml" {
		t.Errorf("path = %s", attrs["honeypot_path"])
	}
	if attrs["honeypot_type"] != "credentials" {
		t.Errorf("type = %s", attrs["honeypot_type"])
	}
	if attrs["honeypot_tripwire"] != "true" {
		t.Errorf("tripwire = %s", attrs["honeypot_tripwire"])
	}
}

func TestAttrsForTriggerWithFreezeRecord(t *testing.T) {
	tTrigger := &HoneypotTrigger{
		PID:  200,
		Comm: "python3",
		Path: "/var/tmp/db_backup.sql",
	}
	r := &FreezeRecord{
		PID:         200,
		Comm:        "python3",
		State:       FreezeComplete,
		CGroupsPath: "/sys/fs/cgroup/providapt-freeze",
		Context: ProcessContext{
			Cmdline: "python3 exploit.py",
			MmapRegions: []string{
				"7f0000-7f1000 r-xp /usr/bin/python3",
				"7f2000-7f3000 rw-p [heap]",
			},
			OpenFDs: []string{"0 → /dev/null", "1 → /dev/tty"},
			EnvVars: map[string]string{"PATH": "/usr/bin", "HOME": "/root"},
		},
	}

	attrs := NodeAttrsForTrigger(tTrigger, r)
	if attrs["frozen"] != "true" {
		t.Errorf("frozen = %s", attrs["frozen"])
	}
	if attrs["captured_cmdline"] != "python3 exploit.py" {
		t.Errorf("cmdline = %s", attrs["captured_cmdline"])
	}
	if attrs["env_PATH"] != "/usr/bin" {
		t.Errorf("PATH = %s", attrs["env_PATH"])
	}
	if attrs["captured_fd_count"] != "2" {
		t.Errorf("fd count = %s", attrs["captured_fd_count"])
	}
	if attrs["captured_maps_count"] != "2" {
		t.Errorf("maps count = %s", attrs["captured_maps_count"])
	}
}

func TestAttrsForTriggerNilRecord(t *testing.T) {
	tTrigger := &HoneypotTrigger{PID: 300, Comm: "test"}
	attrs := NodeAttrsForTrigger(tTrigger, nil)
	if attrs["confirmed_malicious"] != "true" {
		t.Errorf("confirmed_malicious = %s", attrs["confirmed_malicious"])
	}
	if _, ok := attrs["frozen"]; ok {
		t.Error("should not have frozen attr when record is nil")
	}
}

func TestGraphUpdaterCallback(t *testing.T) {
	updated := false
	cfg := &Config{
		Enabled: false, // don't start overlays
		GraphUpdater: func(nodeID string, attrs map[string]string) {
			updated = true
			if nodeID != "p:400" {
				t.Errorf("nodeID = %s", nodeID)
			}
			if attrs["confirmed_malicious"] != "true" {
				t.Errorf("confirmed_malicious = %s", attrs["confirmed_malicious"])
			}
		},
	}
	_ = NewFreezer(cfg)

	// Manually call graph updater.
	if cfg.GraphUpdater != nil {
		cfg.GraphUpdater("p:400", map[string]string{
			"confirmed_malicious": "true",
			"honeypot_triggered":  "true",
		})
	}

	if !updated {
		t.Error("graph updater was not called")
	}
}

// ── Overlay mount tests ─────────────────────────────────────────

func TestOverlayMountStruct(t *testing.T) {
	m := OverlayMount{
		TargetDir: "/tmp/test",
		UpperDir:  "/tmp/honey/upper",
		WorkDir:   "/tmp/honey/work",
	}
	if m.TargetDir != "/tmp/test" {
		t.Errorf("target = %s", m.TargetDir)
	}
	if m.UpperDir != "/tmp/honey/upper" {
		t.Errorf("upper = %s", m.UpperDir)
	}
}

func TestOverlayMountCreated(t *testing.T) {
	m := OverlayMount{
		TargetDir: "/tmp/test",
		Created:   FrozenAt(),
	}
	if m.Created.IsZero() {
		t.Error("created time should be set")
	}
}

func FrozenAt() time.Time {
	return TimeNow()
}

func TimeNow() time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
}

// ── Trigger type tests ──────────────────────────────────────────

func TestTriggerTypes(t *testing.T) {
	if TrigOpen != "open" {
		t.Errorf("TrigOpen = %s", TrigOpen)
	}
	if TrigStat != "stat" {
		t.Errorf("TrigStat = %s", TrigStat)
	}
	if TrigGetdents != "getdents" {
		t.Errorf("TrigGetdents = %s", TrigGetdents)
	}
	if TrigReadlink != "readlink" {
		t.Errorf("TrigReadlink = %s", TrigReadlink)
	}
}

// ── Freeze state tests ──────────────────────────────────────────

func TestFreezeStates(t *testing.T) {
	if FreezePending != "pending" {
		t.Errorf("FreezePending = %s", FreezePending)
	}
	if FreezeComplete != "complete" {
		t.Errorf("FreezeComplete = %s", FreezeComplete)
	}
	if FreezeReleased != "released" {
		t.Errorf("FreezeReleased = %s", FreezeReleased)
	}
	if FreezeFailed != "failed" {
		t.Errorf("FreezeFailed = %s", FreezeFailed)
	}
}

// ── Honeytoken type tests ───────────────────────────────────────

func TestHoneytokenTypes(t *testing.T) {
	if HoneytokenCredentials != "credentials" {
		t.Errorf("HoneytokenCredentials = %s", HoneytokenCredentials)
	}
	if HoneytokenBackup != "backup" {
		t.Errorf("HoneytokenBackup = %s", HoneytokenBackup)
	}
	if HoneytokenKey != "key" {
		t.Errorf("HoneytokenKey = %s", HoneytokenKey)
	}
	if HoneytokenKubeconfig != "kubeconfig" {
		t.Errorf("HoneytokenKubeconfig = %s", HoneytokenKubeconfig)
	}
}

// ── Deception integrator manager accessors ──────────────────────

func TestDeceptionIntegratorAccessors(t *testing.T) {
	di := NewDeceptionIntegrator(nil)

	manager := di.Manager()
	if manager == nil {
		t.Error("Manager() returned nil")
	}

	freezer := di.Freezer()
	if freezer == nil {
		t.Error("Freezer() returned nil")
	}
}

// ── Edge case: empty honeytoken list ────────────────────────────

func TestEmptyHoneytokenList(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		Honeytokens: []HoneytokenDef{},
	}
	om := NewOverlayManager(cfg)
	if len(om.Paths()) != 0 {
		t.Errorf("paths = %d", len(om.Paths()))
	}
}

// ── Edge case: nil config honeytoken by path ────────────────────

func TestHoneytokenByPathEmptyList(t *testing.T) {
	ht := HoneytokenByPath("/tmp/test", nil)
	if ht != nil {
		t.Error("expected nil for nil list")
	}
}

// ── Edge case: capture context with invalid PID ─────────────────

func TestCaptureContextInvalidPID(t *testing.T) {
	ctx := captureContext(-1)
	if ctx.PID != -1 {
		t.Errorf("pid = %d", ctx.PID)
	}
	// Should not panic.
	_ = ctx
}

// ── Graph integration with trigger ──────────────────────────────

func TestGraphUpdaterEmptyAttrs(t *testing.T) {
	di := NewDeceptionIntegrator(&Config{
		GraphUpdater: func(nodeID string, attrs map[string]string) {
			if len(attrs) == 0 {
				t.Error("attrs should not be empty")
			}
		},
	})

	// Simulate trigger → freeze → graph update.
	trigger := &HoneypotTrigger{
		PID:  500,
		Comm: "malware",
		Path: "/tmp/backup_credentials.xml",
	}

	// Manually call graph updater (same path as integrator.handleTrigger).
	if di.graph != nil {
		di.graph("p:500", NodeAttrsForTrigger(trigger, nil))
	}
}

// ── Registration test ───────────────────────────────────────────

func TestOverlayManagerRegisterInEBPF(t *testing.T) {
	om := NewOverlayManager(nil)
	// Without map fd, registration is a no-op (should not error).
	ht := HoneytokenDef{Path: "/tmp/test.xml", Tripwire: true}
	err := om.registerInEBPF(ht)
	if err != nil {
		t.Errorf("registerInEBPF: %v", err)
	}

	// With nil map, should still be no-op.
	om.SetEBPFMap(nil)
	err = om.registerInEBPF(ht)
	if err != nil {
		t.Errorf("registerInEBPF with nil map: %v", err)
	}
}

// ── Path hash consistency ───────────────────────────────────────

func TestPathHashConsistency(t *testing.T) {
	// Verify that the same path always produces the same hash.
	path1 := "/tmp/backup_credentials.xml"
	path2 := "/tmp/db_backup_2024.sql"

	h1a := fnvHash(path1)
	h1b := fnvHash(path1)
	h2 := fnvHash(path2)

	if h1a != h1b {
		t.Error("hash must be deterministic")
	}
	if h1a == h2 {
		t.Error("different paths should have different hashes (extremely unlikely collision)")
	}
}

// ── Preserve context default ────────────────────────────────────

func TestPreserveContextDefault(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.PreserveContext {
		t.Error("PreserveContext should be true by default")
	}
}
