package pebblestore

import (
	"testing"
)

// ─── VersionTracker tests ───────────────────────────────────

func TestNewVersionTracker(t *testing.T) {
	vt := NewVersionTracker()
	if vt == nil {
		t.Fatal("NewVersionTracker returned nil")
	}
}

func TestInitVersion(t *testing.T) {
	vt := NewVersionTracker()
	id := vt.InitVersion(1000, 8, 3)
	if id != "v:1000:8:3:1" {
		t.Errorf("InitVersion = %q", id)
	}
}

func TestNextVersion(t *testing.T) {
	vt := NewVersionTracker()
	prev, next := vt.NextVersion(1000, 8, 3)
	if prev != "v:1000:8:3:1" {
		t.Errorf("prev = %q", prev)
	}
	if next != "v:1000:8:3:2" {
		t.Errorf("next = %q", next)
	}

	// Third version
	prev2, next2 := vt.NextVersion(1000, 8, 3)
	if prev2 != "v:1000:8:3:2" {
		t.Errorf("prev2 = %q", prev2)
	}
	if next2 != "v:1000:8:3:3" {
		t.Errorf("next2 = %q", next2)
	}
}

func TestLatestVersion(t *testing.T) {
	vt := NewVersionTracker()
	vt.NextVersion(2000, 8, 3)
	vt.NextVersion(2000, 8, 3)
	latest := vt.LatestVersion(2000, 8, 3)
	if latest != "v:2000:8:3:2" {
		t.Errorf("latest = %q", latest)
	}
}

func TestIndependentVersions(t *testing.T) {
	vt := NewVersionTracker()
	vt.NextVersion(100, 8, 3) // file A
	vt.NextVersion(200, 8, 3) // file B — independent counter

	aVer := vt.CurrentVersion(100, 8, 3)
	bVer := vt.CurrentVersion(200, 8, 3)

	if aVer != 2 {
		t.Errorf("file A version = %d", aVer)
	}
	if bVer != 2 {
		t.Errorf("file B version = %d", bVer)
	}
}

// ─── VersionID tests ────────────────────────────────────────

func TestVersionID(t *testing.T) {
	id := VersionID(5000, 8, 3, 1)
	if id != "v:5000:8:3:1" {
		t.Errorf("VersionID = %q", id)
	}
}

func TestBaseNodeID(t *testing.T) {
	id := BaseNodeID(5000, 8, 3)
	if id != "f:5000:8:3" {
		t.Errorf("BaseNodeID = %q", id)
	}
}

// ─── VersionStore tests ─────────────────────────────────────

func TestNewVersionStore(t *testing.T) {
	vs := NewVersionStore()
	if vs == nil {
		t.Fatal("NewVersionStore returned nil")
	}
}

func TestRecordWrite(t *testing.T) {
	vs := NewVersionStore()
	verID, rec := vs.RecordWrite(3000, 8, 3, 100, "bash", 1000)

	if rec.Inode != 3000 {
		t.Errorf("inode = %d", rec.Inode)
	}
	if rec.TriggerPID != 100 {
		t.Errorf("PID = %d", rec.TriggerPID)
	}
	if rec.TriggerComm != "bash" {
		t.Errorf("comm = %s", rec.TriggerComm)
	}
	if rec.PrevVersion != "v:3000:8:3:1" {
		t.Errorf("prev = %s", rec.PrevVersion)
	}
	if verID != "v:3000:8:3:2" {
		t.Errorf("verID = %s", verID)
	}
}

func TestRecordRead(t *testing.T) {
	vs := NewVersionStore()

	// First write
	_, writeRec := vs.RecordWrite(4000, 8, 3, 100, "vim", 1000)

	// Read by another process
	readRec := vs.RecordRead(4000, 8, 3, 200, "cat", 2000)
	if readRec == nil {
		t.Fatal("RecordRead returned nil")
	}

	// Read should see the latest version (v2 after write)
	if readRec.VersionNum != 2 {
		t.Errorf("read version = %d, want 2", readRec.VersionNum)
	}

	_ = writeRec
}

func TestGetVersion(t *testing.T) {
	vs := NewVersionStore()
	verID, _ := vs.RecordWrite(5000, 8, 3, 100, "bash", 1000)

	rec := vs.GetVersion(verID)
	if rec == nil {
		t.Fatal("GetVersion returned nil")
	}
	if rec.TriggerComm != "bash" {
		t.Errorf("comm = %s", rec.TriggerComm)
	}
}

func TestGetHistory(t *testing.T) {
	vs := NewVersionStore()

	// Write three versions
	for i := 0; i < 3; i++ {
		vs.RecordWrite(6000, 8, 3, uint32(100+i), "proc", uint64(i*1000))
	}

	history := vs.GetHistory(6000, 8, 3)
	if len(history) != 3 {
		t.Errorf("history length = %d, want 3", len(history))
	}

	// Verify ordering
	for i, rec := range history {
		if rec.VersionNum != int64(i+2) { // starts at 2 (v1 is implicit)
			t.Errorf("history[%d] version = %d", i, rec.VersionNum)
		}
	}
}

func TestVersionCount(t *testing.T) {
	vs := NewVersionStore()
	vs.RecordWrite(100, 8, 3, 1, "a", 0)
	vs.RecordWrite(200, 8, 3, 2, "b", 0)
	vs.RecordWrite(300, 8, 3, 3, "c", 0)

	if vs.VersionCount() != 3 {
		t.Errorf("count = %d", vs.VersionCount())
	}
}

func TestProcessEdge(t *testing.T) {
	rec := &VersionRecord{
		PrevVersion: "v:100:8:3:1",
		VersionID:   "v:100:8:3:2",
		TriggerPID:  100,
	}
	edge := rec.ProcessEdge()
	if edge != "v:100:8:3:1 ──wasDerivedFrom──▶ p:100 ──wasGeneratedBy──▶ v:100:8:3:2" {
		t.Errorf("edge = %s", edge)
	}
}
