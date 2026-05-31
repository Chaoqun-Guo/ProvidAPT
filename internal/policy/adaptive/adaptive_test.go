package adaptive

import (
	"testing"
	"time"
)

// ─── Mock BPF map ───────────────────────────────────────────

type mockBPF struct {
	data map[uint32]uint32
}

func newMockBPF() *mockBPF {
	return &mockBPF{data: make(map[uint32]uint32)}
}
func (m *mockBPF) Put(k, v interface{}) error { m.data[k.(uint32)] = v.(uint32); return nil }
func (m *mockBPF) Delete(k interface{}) error { delete(m.data, k.(uint32)); return nil }

// ─── Level tests ────────────────────────────────────────────

func TestLevelStrings(t *testing.T) {
	if LevelDefault.String() != "DEFAULT" {
		t.Errorf("LevelDefault = %s", LevelDefault)
	}
	if LevelSuspicious.String() != "SUSPICIOUS" {
		t.Errorf("LevelSuspicious = %s", LevelSuspicious)
	}
	if LevelInvestigating.String() != "INVESTIGATING" {
		t.Errorf("LevelInvestigating = %s", LevelInvestigating)
	}
}

func TestLevelCapabilities(t *testing.T) {
	if len(LevelDefault.Capabilities()) != 3 {
		t.Errorf("LevelDefault caps = %d", len(LevelDefault.Capabilities()))
	}
	if len(LevelSuspicious.Capabilities()) != 6 {
		t.Errorf("LevelSuspicious caps = %d", len(LevelSuspicious.Capabilities()))
	}
	if len(LevelInvestigating.Capabilities()) != 9 {
		t.Errorf("LevelInvestigating caps = %d", len(LevelInvestigating.Capabilities()))
	}
}

func TestLevelThresholds(t *testing.T) {
	if LevelDefault.AlertThreshold() != 0 {
		t.Errorf("default threshold = %.0f", LevelDefault.AlertThreshold())
	}
	if LevelInvestigating.AlertThreshold() != 20.0 {
		t.Errorf("investigating threshold = %.0f", LevelInvestigating.AlertThreshold())
	}
}

func TestLevelDescriptions(t *testing.T) {
	if LevelDefault.Description() == "" {
		t.Error("empty description")
	}
}

// ─── Controller tests ───────────────────────────────────────

func TestNewController(t *testing.T) {
	ac := New(nil)
	if ac == nil {
		t.Fatal("New returned nil")
	}
}

func TestDefaultLevel(t *testing.T) {
	ac := New(nil)
	if l := ac.GetLevel(9999); l != LevelDefault {
		t.Errorf("default level = %s", l)
	}
}

func TestUpgradeToSuspicious(t *testing.T) {
	ac := New(newMockBPF())
	level := ac.Upgrade(100, "rare path access")
	if level != LevelSuspicious {
		t.Errorf("expected SUSPICIOUS, got %s", level)
	}
	if ac.GetLevel(100) != LevelSuspicious {
		t.Error("level not stored")
	}
}

func TestUpgradeToInvestigating(t *testing.T) {
	ac := New(newMockBPF())
	ac.upgradeCooldown = time.Millisecond
	var level Level
	for i := 0; i < 3; i++ {
		level = ac.Upgrade(200, "repeated alert")
	}
	if level != LevelInvestigating {
		t.Errorf("expected INVESTIGATING after 3 alerts, got %s", level)
	}
}

func TestFastUpgradeOnHighScore(t *testing.T) {
	ac := New(newMockBPF())
	level := ac.OnAlert(300, 25.0, "high score alert")
	if level != LevelInvestigating {
		t.Errorf("expected INVESTIGATING for score 25, got %s", level)
	}
}

func TestNoUpgradeForLowScore(t *testing.T) {
	ac := New(newMockBPF())
	level := ac.OnAlert(400, 2.0, "trivial event")
	if level != LevelDefault {
		t.Errorf("expected DEFAULT for score 2, got %s", level)
	}
}

func TestDowngrade(t *testing.T) {
	ac := New(newMockBPF())
	ac.Upgrade(500, "test")
	if ac.GetLevel(500) != LevelSuspicious {
		t.Fatal("upgrade failed")
	}
	ac.Downgrade(500)
	if ac.GetLevel(500) != LevelDefault {
		t.Error("downgrade failed")
	}
}

func TestFeedbackLoopDowngrade(t *testing.T) {
	ac := New(newMockBPF())
	ac.downgradeAfter = 10 * time.Millisecond
	ac.upgradeCooldown = time.Millisecond

	// Upgrade
	ac.Upgrade(600, "test")
	if ac.GetLevel(600) != LevelSuspicious {
		t.Fatal("upgrade failed")
	}

	// Wait for downgrade
	time.Sleep(20 * time.Millisecond)
	n := ac.Tick()
	if n != 1 {
		t.Errorf("expected 1 downgrade, got %d", n)
	}
	if ac.GetLevel(600) != LevelDefault {
		t.Error("should be default after tick")
	}
}

func TestFeedbackLoopSkipsRecent(t *testing.T) {
	ac := New(newMockBPF())
	ac.downgradeAfter = time.Hour // long cooldown

	ac.Upgrade(700, "test")
	n := ac.Tick()
	if n != 0 {
		t.Errorf("expected 0 downgrades, got %d", n)
	}
}

func TestOnAlertMultiple(t *testing.T) {
	ac := New(newMockBPF())
	level := ac.OnAlert(800, 10.0, "first alert")
	if level != LevelSuspicious {
		t.Errorf("expected SUSPICIOUS, got %s", level)
	}
	// Second alert with high score — fast-path to INVESTIGATING
	level = ac.OnAlert(800, 20.0, "second alert")
	if level != LevelInvestigating {
		t.Errorf("expected INVESTIGATING after 2nd alert, got %s", level)
	}
}

func TestActiveProcesses(t *testing.T) {
	ac := New(newMockBPF())
	ac.Upgrade(900, "test")
	ac.Upgrade(901, "test")

	procs := ac.ActiveProcesses()
	if len(procs) != 2 {
		t.Errorf("expected 2 active procs, got %d", len(procs))
	}
	for _, p := range procs {
		if p.Level != LevelSuspicious {
			t.Errorf("proc %d level = %s", p.PID, p.Level)
		}
		if p.Since < 0 {
			t.Errorf("proc %d zero since", p.PID)
		}
	}
}

func TestStats(t *testing.T) {
	ac := New(newMockBPF())
	ac.Upgrade(1000, "test")
	ac.Upgrade(1001, "test")
	ac.Downgrade(1000)

	stats := ac.Stats()
	if stats["total_upgrades"].(int) != 2 {
		t.Errorf("upgrades = %d", stats["total_upgrades"])
	}
	if stats["total_downgrades"].(int) != 1 {
		t.Errorf("downgrades = %d", stats["total_downgrades"])
	}
}

func TestBPFMapIntegration(t *testing.T) {
	bpf := newMockBPF()
	ac := New(bpf)

	ac.Upgrade(1100, "test")
	if bpf.data[1100] != uint32(LevelSuspicious) {
		t.Errorf("bpf map value = %d", bpf.data[1100])
	}

	ac.Downgrade(1100)
	if _, ok := bpf.data[1100]; ok {
		t.Error("bpf map entry should be deleted after downgrade")
	}
}

func TestLevelFor(t *testing.T) {
	s := LevelFor(LevelDefault, LevelSuspicious)
	if s != "DEFAULT→SUSPICIOUS" {
		t.Errorf("LevelFor = %q", s)
	}
	s2 := LevelFor(LevelDefault, LevelDefault)
	if s2 != "DEFAULT" {
		t.Errorf("LevelFor same = %q", s2)
	}
}

func TestConcurrentAccess(t *testing.T) {
	ac := New(newMockBPF())
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			ac.Upgrade(i, "concurrent")
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 100; i++ {
			ac.GetLevel(i)
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 100; i++ {
			ac.Stats()
		}
		done <- true
	}()

	<-done
	<-done
	<-done
}

func TestDowngradeTime(t *testing.T) {
	if LevelSuspicious.DowngradeAfter() != 600 {
		t.Errorf("Suspicious cooldown = %d", LevelSuspicious.DowngradeAfter())
	}
	if LevelInvestigating.DowngradeAfter() != 300 {
		t.Errorf("Investigating cooldown = %d", LevelInvestigating.DowngradeAfter())
	}
}
