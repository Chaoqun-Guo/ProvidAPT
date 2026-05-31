package incident

import (
	"strings"
	"testing"
	"time"
)

// ─── Incident clustering tests ──────────────────────────────

func TestNewIncidentCluster(t *testing.T) {
	ic := NewIncidentCluster()
	if ic == nil {
		t.Fatal("NewIncidentCluster returned nil")
	}
}

func TestIngestCreatesIncident(t *testing.T) {
	ic := NewIncidentCluster()
	alert := &AlertNode{ID: "A1", Type: "file_write", Comm: "bash", Target: "/etc/shadow", Score: 50}

	inc := ic.Ingest(alert)
	if inc == nil {
		t.Fatal("Ingest returned nil")
	}
	if inc.TotalAlerts != 1 {
		t.Errorf("alerts = %d", inc.TotalAlerts)
	}
}

func TestIngestSameIncident(t *testing.T) {
	ic := NewIncidentCluster()

	a1 := &AlertNode{ID: "A1", Type: "file_write", Comm: "bash", Target: "/etc/shadow", Score: 50}
	// Same target → connects to existing incident
	a2 := &AlertNode{ID: "A2", Type: "net_connect", Comm: "bash", Target: "/etc/shadow", Score: 30}

	ic.Ingest(a1)
	inc2 := ic.Ingest(a2)

	if inc2.TotalAlerts != 2 {
		t.Errorf("total alerts = %d, want 2", inc2.TotalAlerts)
	}
}

func TestSeparateIncidents(t *testing.T) {
	ic := NewIncidentCluster()

	a1 := &AlertNode{ID: "A1", Type: "write", Comm: "bash", Target: "/etc/shadow", Score: 50}
	a2 := &AlertNode{ID: "A2", Type: "write", Comm: "python", Target: "/tmp/test", Score: 10}

	inc1 := ic.Ingest(a1)
	inc2 := ic.Ingest(a2)

	if inc1.ID == inc2.ID {
		t.Log("alerts merged (expected if they share comm)")
	} else {
		t.Log("separate incidents created")
	}
}

func TestActiveIncidents(t *testing.T) {
	ic := NewIncidentCluster()
	ic.Ingest(&AlertNode{ID: "A1", Score: 10})

	active := ic.ActiveIncidents()
	if len(active) != 1 {
		t.Errorf("active = %d", len(active))
	}
}

func TestResolveIncident(t *testing.T) {
	ic := NewIncidentCluster()
	inc := ic.Ingest(&AlertNode{ID: "A1", Score: 10})
	ic.ResolveIncident(inc.ID)

	active := ic.ActiveIncidents()
	if len(active) != 0 {
		t.Error("incident should be resolved")
	}
}

func TestStats(t *testing.T) {
	ic := NewIncidentCluster()
	ic.Ingest(&AlertNode{ID: "A1", Score: 10})
	ic.Ingest(&AlertNode{ID: "A2", Score: 20})

	stats := ic.Stats()
	if stats["total_alerts"].(int) != 2 {
		t.Errorf("alerts = %d", stats["total_alerts"])
	}
}

// ─── Risk scoring tests ─────────────────────────────────────

func TestNewRiskScorer(t *testing.T) {
	rs := NewRiskScorer(nil)
	if rs == nil {
		t.Fatal("NewRiskScorer returned nil")
	}
}

func TestScoreAlert(t *testing.T) {
	rs := NewRiskScorer(nil)

	// Basic exec
	s1 := rs.ScoreAlert("exec", "/bin/bash", "bash", false, 1)
	if s1 < 20 {
		t.Errorf("exec score = %.0f", s1)
	}

	// Memfd (high risk)
	s2 := rs.ScoreAlert("memfd", "", "python", false, 1)
	if s2 < 60 {
		t.Errorf("memfd score = %.0f", s2)
	}

	// Mprotect (critical)
	s3 := rs.ScoreAlert("mprotect", "", "bash", false, 1)
	if s3 < 100 {
		t.Errorf("mprotect score = %.0f", s3)
	}
}

func TestScoreWithSensitivePath(t *testing.T) {
	rs := NewRiskScorer(nil)
	score := rs.ScoreAlert("file_write", "/etc/shadow", "bash", false, 1)
	if score < 20 {
		t.Errorf("shadow write score = %.0f", score)
	}
}

func TestScoreWithTaint(t *testing.T) {
	rs := NewRiskScorer(nil)
	clean := rs.ScoreAlert("net_connect", "5.6.7.8", "curl", false, 1)
	tainted := rs.ScoreAlert("net_connect", "5.6.7.8", "curl", true, 1)
	if tainted <= clean {
		t.Error("tainted should score higher")
	}
	t.Logf("Clean: %.0f, Tainted: %.0f", clean, tainted)
}

func TestScoreWithPathLength(t *testing.T) {
	rs := NewRiskScorer(nil)
	s1 := rs.ScoreAlert("exec", "/bin/sh", "bash", false, 1)
	s5 := rs.ScoreAlert("exec", "/bin/sh", "bash", false, 5)
	if s5 <= s1 {
		t.Error("longer path should score higher")
	}
}

func TestClassify(t *testing.T) {
	rs := NewRiskScorer(nil)
	if rs.Classify(10) != "LOW" {
		t.Errorf("10 -> %s", rs.Classify(10))
	}
	if rs.Classify(50) != "MEDIUM" {
		t.Errorf("50 -> %s", rs.Classify(50))
	}
	if rs.Classify(80) != "HIGH" {
		t.Errorf("80 -> %s", rs.Classify(80))
	}
	if rs.Classify(150) != "CRITICAL" {
		t.Errorf("150 -> %s", rs.Classify(150))
	}
}

// ─── Context enrichment tests ────────────────────────────────

func TestNewReportGenerator(t *testing.T) {
	rg := NewReportGenerator()
	if rg == nil {
		t.Fatal("NewReportGenerator returned nil")
	}
}

func TestGenerateReport(t *testing.T) {
	rg := NewReportGenerator()
	inc := &Incident{
		ID: "INC-1", TotalAlerts: 2, RiskScore: 85,
		AlertIDs: []string{"A1", "A2"},
	}
	alerts := []*AlertNode{
		{ID: "A1", Type: "taint", Comm: "curl", PID: 100, Target: "5.6.7.8", Score: 50},
		{ID: "A2", Type: "file_write", Comm: "bash", PID: 200, Target: "/etc/shadow", Score: 35},
	}

	report := rg.Generate(inc, alerts)
	if report == nil {
		t.Fatal("Generate returned nil")
	}
	if report.EntryPoint == "" {
		t.Error("missing entry point")
	}
	if report.Briefing == "" {
		t.Error("missing briefing")
	}
	t.Logf("Briefing:\n%s", report.Briefing)
}

func TestFormatBriefing(t *testing.T) {
	report := &IncidentReport{
		IncidentID:    "INC-1",
		RiskLevel:     "HIGH",
		RiskScore:     85,
		EntryPoint:    "curl (PID 100)",
		FarthestPoint: "/etc/shadow",
	}
	brief := report.FormatBriefing()
	if !strings.Contains(brief, "HIGH") {
		t.Errorf("briefing = %s", brief)
	}
	t.Logf("Briefing: %s", brief)
}

func TestMapTTP(t *testing.T) {
	if mapTTP("memfd") != "T1055 (Process Injection)" {
		t.Errorf("memfd -> %s", mapTTP("memfd"))
	}
	if mapTTP("taint") != "T1043 (C2)" {
		t.Errorf("taint -> %s", mapTTP("taint"))
	}
	if mapTTP("shadow") != "T1003 (OS Credential Dumping)" {
		t.Errorf("shadow -> %s", mapTTP("shadow"))
	}
	if mapTTP("normal") != "" {
		t.Errorf("normal -> %s", mapTTP("normal"))
	}
}

// ─── Integration test ───────────────────────────────────────

func TestAlertIntegration(t *testing.T) {
	t.Log("=== Alert Optimization Integration ===")

	// 1. Create alerts
	alerts := []*AlertNode{
		{ID: "A1", Type: "taint", Comm: "curl", PID: 100, Target: "5.6.7.8", Score: 50, Timestamp: now()},
		{ID: "A2", Type: "file_write", Comm: "bash", PID: 101, Target: "/etc/shadow", Score: 35, Timestamp: now()},
		{ID: "A3", Type: "net_connect", Comm: "bash", PID: 101, Target: "5.6.7.8:443", Score: 30, Timestamp: now()},
	}

	// 2. Cluster into incidents
	ic := NewIncidentCluster()
	var firstInc *Incident
	for _, a := range alerts {
		inc := ic.Ingest(a)
		if firstInc == nil {
			firstInc = inc
		}
	}

	t.Logf("Active incidents: %d", len(ic.ActiveIncidents()))
	stats := ic.Stats()
	t.Logf("Stats: %d alerts → %d incidents", stats["total_alerts"], stats["total_incidents"])

	// 3. Score the incident
	rs := NewRiskScorer(nil)
	for _, a := range alerts {
		s := rs.ScoreAlert(a.Type, a.Target, a.Comm, a.Type == "taint", 3)
		t.Logf("  %s: %.0f (%s)", a.ID, s, rs.Classify(s))
	}

	// 4. Generate report
	rg := NewReportGenerator()
	report := rg.Generate(firstInc, alerts)
	t.Logf("\n%s", report.Briefing)
	t.Logf("Brief: %s", report.FormatBriefing())

	if report.RiskLevel == "" {
		t.Error("missing risk level")
	}
	if report.EntryPoint == "" {
		t.Error("missing entry point")
	}
	t.Log("Alert optimization integration OK")
}

func now() time.Time { return time.Now() }
