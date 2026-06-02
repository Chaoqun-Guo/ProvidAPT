package blastradius

import (
	"testing"
	"time"
)

func TestNewBlastRadiusEngine(t *testing.T) {
	bre := NewBlastRadiusEngine()
	if bre == nil {
		t.Fatal("NewBlastRadiusEngine returned nil")
	}
	if bre.maxDepth != 10 {
		t.Errorf("maxDepth = %d, want 10", bre.maxDepth)
	}
}

func TestCalculateSingleHost(t *testing.T) {
	bre := NewBlastRadiusEngine()
	result := bre.Calculate("p:100", "host1", nil)
	if result == nil {
		t.Fatal("Calculate returned nil")
	}
	if result.RootNode != "p:100" {
		t.Errorf("RootNode = %s", result.RootNode)
	}
	if result.RootHost != "host1" {
		t.Errorf("RootHost = %s", result.RootHost)
	}
	if result.TotalHosts != 1 {
		t.Errorf("TotalHosts = %d", result.TotalHosts)
	}
}

func TestCalculateLateralMovement(t *testing.T) {
	bre := NewBlastRadiusEngine()
	edges := []LateralEdge{
		{SourceHost: "host1", TargetHost: "host2", Relation: "ssh", PID: 100, Comm: "ssh"},
		{SourceHost: "host2", TargetHost: "host3", Relation: "ssh", PID: 200, Comm: "ssh"},
	}
	result := bre.Calculate("p:100", "host1", edges)
	if result.TotalHosts != 3 {
		t.Errorf("TotalHosts = %d, want 3", result.TotalHosts)
	}
	if result.MaxDepth != 10 {
		t.Errorf("MaxDepth = %d", result.MaxDepth)
	}
}

func TestCalculateMaxDepth(t *testing.T) {
	bre := NewBlastRadiusEngine()
	bre.maxDepth = 1
	edges := []LateralEdge{
		{SourceHost: "host1", TargetHost: "host2", Relation: "ssh", PID: 100, Comm: "ssh"},
		{SourceHost: "host2", TargetHost: "host3", Relation: "ssh", PID: 200, Comm: "ssh"},
	}
	result := bre.Calculate("p:100", "host1", edges)
	if result.TotalHosts != 2 { // host1 + host2 only (depth limit)
		t.Errorf("TotalHosts = %d, want 2", result.TotalHosts)
	}
}

func TestCalculateDeduplicatesHosts(t *testing.T) {
	bre := NewBlastRadiusEngine()
	edges := []LateralEdge{
		{SourceHost: "host1", TargetHost: "host2", Relation: "ssh", PID: 100, Comm: "ssh"},
		{SourceHost: "host1", TargetHost: "host2", Relation: "scp", PID: 101, Comm: "scp"},
	}
	result := bre.Calculate("p:100", "host1", edges)
	if result.TotalHosts != 2 {
		t.Errorf("TotalHosts = %d, want 2", result.TotalHosts)
	}
}

func TestGetHostProcesses(t *testing.T) {
	bre := NewBlastRadiusEngine()
	edges := []LateralEdge{
		{SourceHost: "host1", TargetHost: "host2", Relation: "ssh", PID: 100, Comm: "ssh"},
		{SourceHost: "host1", TargetHost: "host2", Relation: "scp", PID: 101, Comm: "scp"},
	}
	procs := bre.getHostProcesses("host1", edges)
	if len(procs) != 2 {
		t.Errorf("processes = %d, want 2", len(procs))
	}
}

func TestGetHostFilesTaintedSCP(t *testing.T) {
	bre := NewBlastRadiusEngine()
	edges := []LateralEdge{
		{SourceHost: "host1", TargetHost: "host2", Relation: "scp", PID: 100, Comm: "scp", Tainted: true},
	}
	files := bre.getHostFiles("host1", edges)
	if len(files) == 0 {
		t.Error("expected files for tainted scp")
	}
	if len(files) >= 1 && files[0] != "transferred_by_scp(PID 100)" {
		t.Errorf("file[0] = %q", files[0])
	}
}

func TestGetHostFilesUnrelated(t *testing.T) {
	bre := NewBlastRadiusEngine()
	edges := []LateralEdge{
		{SourceHost: "host1", TargetHost: "host2", Relation: "ssh", PID: 100, Comm: "ssh", Tainted: false},
	}
	files := bre.getHostFiles("host1", edges)
	if len(files) != 0 {
		t.Errorf("expected no files for untrained ssh, got %d", len(files))
	}
}

func TestGetHostNetworks(t *testing.T) {
	bre := NewBlastRadiusEngine()
	edges := []LateralEdge{
		{SourceHost: "host1", TargetHost: "host2", Relation: "ssh", PID: 100, Comm: "ssh", Tainted: true},
	}
	nets := bre.getHostNetworks("host1", edges)
	if len(nets) == 0 {
		t.Error("expected networks for tainted edge")
	}
}

func TestCalcHostRisk(t *testing.T) {
	bre := NewBlastRadiusEngine()
	impact := HostImpact{
		Processes: []string{"ssh", "bash"},
		Files:     []string{"/etc/shadow"},
		Networks:  []string{"10.0.0.0/8"},
	}
	score := bre.calcHostRisk(impact)
	// 2*10 + 1*5 + 1*15 = 40
	if score != 40 {
		t.Errorf("risk = %f, want 40", score)
	}
}

func TestCalcHostRiskCaps(t *testing.T) {
	bre := NewBlastRadiusEngine()
	impact := HostImpact{
		Processes: make([]string, 20), // 20*10 = 200 → capped at 100
	}
	score := bre.calcHostRisk(impact)
	if score != 100 {
		t.Errorf("risk = %f, want 100", score)
	}
}

func TestBlastRadiusSummary(t *testing.T) {
	result := &BlastRadiusResult{
		RootNode: "p:100",
		RootHost: "host1",
		AffectedHosts: []HostImpact{
			{HostID: "host1", Processes: []string{"bash"}, RiskScore: 10},
			{HostID: "host2", Processes: []string{"sshd"}, IsCritical: true, RiskScore: 60},
		},
		TotalHosts: 2,
		TotalAssets: 2,
	}
	s := result.Summary()
	if s == "" {
		t.Error("empty summary")
	}
	if !contains(s, "CRITICAL") {
		t.Error("summary should contain CRITICAL for host2")
	}
}

func TestUnique(t *testing.T) {
	result := unique([]string{"a", "b", "a", "c"})
	if len(result) != 3 {
		t.Errorf("len = %d, want 3", len(result))
	}
}

// ── CredentialCorrelator tests ────────────────────────

func TestNewCredentialCorrelator(t *testing.T) {
	cc := NewCredentialCorrelator()
	if cc == nil {
		t.Fatal("NewCredentialCorrelator returned nil")
	}
	if cc.window != time.Hour {
		t.Errorf("window = %v", cc.window)
	}
}

func TestRecordLSASS(t *testing.T) {
	cc := NewCredentialCorrelator()
	inc := cc.RecordLSASS("host1", 100, "mimikatz")
	if inc == nil {
		t.Fatal("RecordLSASS returned nil")
	}
	if inc.LSASSEvent.HostID != "host1" {
		t.Errorf("HostID = %s", inc.LSASSEvent.HostID)
	}
	if inc.LSASSEvent.Comm != "mimikatz" {
		t.Errorf("Comm = %s", inc.LSASSEvent.Comm)
	}
}

func TestRecordRemoteLoginNoCorrelation(t *testing.T) {
	cc := NewCredentialCorrelator()
	inc := cc.RecordRemoteLogin("host1", "host2", "admin", 200, "ssh")
	if inc != nil {
		t.Error("expected nil without prior LSASS event")
	}
}

func TestRecordRemoteLoginWithCorrelation(t *testing.T) {
	cc := NewCredentialCorrelator()
	cc.RecordLSASS("host1", 100, "mimikatz")
	inc := cc.RecordRemoteLogin("host1", "host2", "admin", 200, "ssh")
	if inc == nil {
		t.Fatal("expected correlation with prior LSASS event")
	}
	if inc.Identity != "admin" {
		t.Errorf("Identity = %s", inc.Identity)
	}
	if !inc.Alerted {
		t.Error("should be alerted")
	}
}

func TestRecordRemoteLoginWrongHost(t *testing.T) {
	cc := NewCredentialCorrelator()
	cc.RecordLSASS("host1", 100, "mimikatz")
	// Login from different host → no correlation
	inc := cc.RecordRemoteLogin("host3", "host4", "admin", 200, "ssh")
	if inc != nil {
		t.Error("expected nil for different source host")
	}
}

func TestIncidents(t *testing.T) {
	cc := NewCredentialCorrelator()
	cc.RecordLSASS("host1", 100, "mimikatz")
	incs := cc.Incidents()
	if len(incs) != 1 {
		t.Errorf("incidents = %d", len(incs))
	}
}

func TestCredentialIncidentSummary(t *testing.T) {
	inc := &CredentialIncident{
		LSASSEvent: &LSASSEvent{HostID: "host1", Comm: "mimikatz", Timestamp: time.Now()},
		Identity:   "admin",
	}
	s := inc.Summary()
	if !contains(s, "CRED") {
		t.Error("summary should contain CRED")
	}
}

// ── AnomalousPathDetector tests ───────────────────────

func TestNewAnomalousPathDetector(t *testing.T) {
	apd := NewAnomalousPathDetector()
	if apd == nil {
		t.Fatal("NewAnomalousPathDetector returned nil")
	}
	if len(apd.templates) == 0 {
		t.Error("expected default templates")
	}
}

func TestCheckPathMatched(t *testing.T) {
	apd := NewAnomalousPathDetector()
	// This should match user→web→api→db
	alert := apd.CheckPath(
		[]string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
		[]string{"user-pc", "web-server", "api-server", "database"},
	)
	if alert != nil {
		t.Errorf("expected nil for matched path, got alert: %s", alert.Description)
	}
}

func TestCheckPathAnomalous(t *testing.T) {
	apd := NewAnomalousPathDetector()
	alert := apd.CheckPath(
		[]string{"10.0.0.1", "10.0.0.5"},
		[]string{"user-pc", "database"},
	)
	if alert == nil {
		t.Fatal("expected alert for anomalous path")
	}
	if alert.Severity != "HIGH" {
		t.Errorf("Severity = %s", alert.Severity)
	}
}

func TestCheckPathShort(t *testing.T) {
	apd := NewAnomalousPathDetector()
	alert := apd.CheckPath([]string{"host1"}, []string{"user-pc"})
	if alert != nil {
		t.Error("expected nil for single-host path")
	}
}

func TestMatchTemplate(t *testing.T) {
	apd := NewAnomalousPathDetector()
	if !apd.matchTemplate([]string{"user-pc", "web-server"}, []string{"user-pc", "web-server"}) {
		t.Error("should match identical templates")
	}
	if apd.matchTemplate([]string{"user-pc", "web-server"}, []string{"user-pc", "database"}) {
		t.Error("should not match different templates")
	}
	if apd.matchTemplate([]string{"user-pc"}, []string{"user-pc", "web-server"}) {
		t.Error("should not match different lengths")
	}
}

func TestDescribeJumps(t *testing.T) {
	jumps := describeJumps([]string{"10.0.0.1", "10.0.0.2"}, []string{"user-pc", "web-server"})
	if len(jumps) != 2 {
		t.Errorf("len = %d", len(jumps))
	}
	if jumps[0] != "10.0.0.1(user-pc)" {
		t.Errorf("jump[0] = %q", jumps[0])
	}
}

func TestClassifyAnomaly(t *testing.T) {
	if classifyAnomaly([]string{"user-pc", "jump-server"}) != "jump" {
		t.Error("expected jump classification")
	}
	if classifyAnomaly([]string{"user-pc", "production-server"}) != "escalation" {
		t.Error("expected escalation classification")
	}
	if classifyAnomaly([]string{"user-pc"}) != "unexpected_path" {
		t.Error("expected unexpected_path classification")
	}
}

func TestPathAlerts(t *testing.T) {
	apd := NewAnomalousPathDetector()
	apd.CheckPath([]string{"10.0.0.1", "10.0.0.5"}, []string{"user-pc", "database"})
	alerts := apd.Alerts()
	if len(alerts) != 1 {
		t.Errorf("alerts = %d", len(alerts))
	}
}

func TestDefaultPathTemplates(t *testing.T) {
	if len(DefaultPathTemplates) != 4 {
		t.Errorf("templates = %d", len(DefaultPathTemplates))
	}
}

func TestBlastRadiusAssetsCount(t *testing.T) {
	bre := NewBlastRadiusEngine()
	edges := []LateralEdge{
		{SourceHost: "host1", TargetHost: "host2", Relation: "ssh", PID: 100, Comm: "ssh"},
	}
	result := bre.Calculate("p:100", "host1", edges)
	if result.TotalAssets <= 0 {
		t.Errorf("TotalAssets = %d, want > 0", result.TotalAssets)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
