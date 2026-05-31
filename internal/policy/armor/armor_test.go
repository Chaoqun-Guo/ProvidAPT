package armor

import (
	"os"
	"strings"
	"testing"
	"time"
)

// ── Map audit tests ─────────────────────────────────────────

func TestNewMapAuditor(t *testing.T) {
	ma := NewMapAuditor()
	if ma == nil {
		t.Fatal("NewMapAuditor returned nil")
	}
}

func TestRegisterKnownPID(t *testing.T) {
	ma := NewMapAuditor()
	ma.RegisterKnownPID(100)
	// Should not panic
}

func TestAuditAgentMap(t *testing.T) {
	ma := NewMapAuditor()
	ma.RegisterKnownPID(uint32(os.Getpid()))
	records, err := ma.AuditAgentMap()
	if err != nil {
		t.Logf("AuditAgentMap (requires root): %v", err)
	} else {
		t.Logf("Audit records: %d", len(records))
	}
}

func TestAnomalies(t *testing.T) {
	ma := NewMapAuditor()
	anomalies := ma.Anomalies()
	if anomalies == nil {
		t.Error("Anomalies returned nil")
	}
}

// ── Kallsyms monitor tests ────────────────────────────────

func TestNewKallsymsMonitor(t *testing.T) {
	km := NewKallsymsMonitor()
	if km == nil {
		t.Fatal("NewKallsymsMonitor returned nil")
	}
}

func TestCaptureKallsyms(t *testing.T) {
	km := NewKallsymsMonitor()
	snap, err := km.Capture()
	if err != nil {
		t.Skipf("kallsyms capture: %v (need root)", err)
	}
	if snap.Count == 0 {
		t.Error("no symbols captured")
	} else {
		t.Logf("Captured %d symbols", snap.Count)
	}
}

func TestTakeBaseline(t *testing.T) {
	km := NewKallsymsMonitor()
	err := km.TakeBaseline()
	if err != nil {
		t.Skipf("baseline: %v (need root)", err)
	}
	t.Log("Baseline taken")
}

func TestKallsymsDiff(t *testing.T) {
	km := NewKallsymsMonitor()
	km.TakeBaseline()
	changes, err := km.Diff()
	if err != nil {
		t.Skipf("diff: %v", err)
	}
	t.Logf("Changes: %d", len(changes))
	for _, c := range changes {
		t.Logf("  %s", c)
	}
}

func TestCheckSecurityHooks(t *testing.T) {
	km := NewKallsymsMonitor()
	issues := km.CheckSecurityHooks()
	if len(issues) > 0 {
		t.Logf("Security hook issues: %d", len(issues))
		for _, i := range issues {
			t.Logf("  %s", i)
		}
	} else {
		t.Log("All security hooks present")
	}
}

func TestFtraceCheck(t *testing.T) {
	issues, err := CheckFtraceTrampoline()
	if err != nil {
		t.Skipf("ftrace check: %v", err)
	}
	t.Logf("Ftrace issues: %d", len(issues))
}

// ── Shadow monitor tests ───────────────────────────────────

func TestNewShadowMonitor(t *testing.T) {
	sm := NewShadowMonitor()
	if sm == nil {
		t.Fatal("NewShadowMonitor returned nil")
	}
}

func TestHeartbeat(t *testing.T) {
	sm := NewShadowMonitor()
	sm.RecordHeartbeat()
	sm.CheckHeartbeat()
	status := sm.Status()
	if !status.Heartbeat {
		t.Error("heartbeat should be true after Record")
	}
}

func TestHeartbeatMiss(t *testing.T) {
	sm := NewShadowMonitor()
	// Simulate miss: don't record heartbeat, check after long delay
	sm.status.LastHeartbeat = time.Now().Add(-1 * time.Minute)
	sm.CheckHeartbeat()
	if sm.heartbeatMiss != 1 {
		t.Errorf("miss count = %d", sm.heartbeatMiss)
	}
}

func TestMapIntegrity(t *testing.T) {
	sm := NewShadowMonitor()
	// Without real BPF maps, this should return true with a warning
	ok := sm.CheckMapIntegrity(os.Getpid())
	t.Logf("Map integrity: %v", ok)
}

func TestHookIntegrity(t *testing.T) {
	sm := NewShadowMonitor()
	ok := sm.CheckHookIntegrity()
	t.Logf("Hook integrity: %v", ok)
}

func TestAlertSummary(t *testing.T) {
	sm := NewShadowMonitor()
	summary := sm.AlertSummary()
	if !strings.Contains(summary, "nominal") {
		t.Errorf("unexpected summary: %s", summary)
	}
	sm.status.Alerts = append(sm.status.Alerts, "test alert")
	summary = sm.AlertSummary()
	if !strings.Contains(summary, "test alert") {
		t.Error("alert not in summary")
	}
}

// ── Anti-rootkit scanner tests ─────────────────────────────

func TestNewScanner(t *testing.T) {
	ars := NewAntiRootkitScanner(os.Getpid())
	if ars == nil {
		t.Fatal("NewScanner returned nil")
	}
}

func TestScannerInit(t *testing.T) {
	ars := NewAntiRootkitScanner(os.Getpid())
	err := ars.Init()
	if err != nil {
		t.Logf("Init: %v", err)
	}
}

func TestScannerScan(t *testing.T) {
	ars := NewAntiRootkitScanner(os.Getpid())
	ars.Init()
	report := ars.Scan()
	if report == nil {
		t.Fatal("Scan returned nil")
	}
	t.Logf("Scan: %s", report.Summary())
	t.Logf("  Issues: %d", len(report.Issues))
	t.Logf("  Shadow heartbeat: %v", report.ShadowStatus.Heartbeat)
}

func TestScannerReportClean(t *testing.T) {
	report := &ScanReport{Time: time.Now()}
	summary := report.Summary()
	if !strings.Contains(summary, "CLEAN") {
		t.Error("empty report should be CLEAN")
	}
}

func TestScannerReportIssues(t *testing.T) {
	report := &ScanReport{
		Time:   time.Now(),
		Issues: []string{"test issue"},
	}
	summary := report.Summary()
	if !strings.Contains(summary, "ISSUES") {
		t.Error("should indicate issues found")
	}
}

// ── Integration test ─────────────────────────────────────

func TestArmorIntegration(t *testing.T) {
	ars := NewAntiRootkitScanner(os.Getpid())
	ars.Init()

	// Run full scan
	report := ars.Scan()
	t.Logf("=== Armor Scan Report ===")
	t.Logf("Time: %s", report.Time)
	t.Logf("Map records: %d", len(report.MapRecords))
	t.Logf("Kallsyms changes: %d", len(report.KallsymsChanges))
	t.Logf("Security hooks missing: %d", len(report.SecurityHooksMissing))
	t.Logf("Shadow heartbeat: %v", report.ShadowStatus.Heartbeat)
	t.Logf("Total issues: %d", len(report.Issues))
	t.Logf("Status: %s", report.Summary())
}
