package chain

import (
	"fmt"
	"testing"
	"time"
)

// ─── Hash chain tests ───────────────────────────────────────

func TestNewChainStore(t *testing.T) {
	cs := NewChainStore()
	if cs == nil {
		t.Fatal("NewChainStore returned nil")
	}
}

func TestAdd(t *testing.T) {
	cs := NewChainStore()
	rec := cs.Add(10, []byte("event data"))
	if rec == nil {
		t.Fatal("Add returned nil")
	}
	if rec.Index != 1 {
		t.Errorf("index = %d", rec.Index)
	}
	if rec.ChainHash == "" {
		t.Error("empty chain hash")
	}
	if rec.HMAC == "" {
		t.Error("empty HMAC")
	}
}

func TestChaining(t *testing.T) {
	cs := NewChainStore()
	r1 := cs.Add(10, []byte("event1"))
	r2 := cs.Add(11, []byte("event2"))

	if r2.PrevHash != r1.ChainHash {
		t.Error("chain linkage broken")
	}
}

func TestVerifyRecord(t *testing.T) {
	cs := NewChainStore()
	rec := cs.Add(10, []byte("test data"))

	if !cs.VerifyRecord(rec) {
		t.Error("valid record should verify")
	}

	// Tamper with the record
	rec.ChainHash = "tampered"
	if cs.VerifyRecord(rec) {
		t.Error("tampered record should not verify")
	}
}

func TestVerifyChain(t *testing.T) {
	cs := NewChainStore()
	for i := 0; i < 10; i++ {
		cs.Add(uint32(i), []byte{byte(i)})
	}

	valid, count := cs.VerifyChain()
	if !valid {
		t.Error("chain should be valid")
	}
	if count != 10 {
		t.Errorf("count = %d", count)
	}
}

func TestLatestHash(t *testing.T) {
	cs := NewChainStore()
	cs.Add(10, []byte("data"))
	hash := cs.LatestHash()
	if len(hash) != 64 { // SHA256 = 64 hex chars
		t.Errorf("hash length = %d", len(hash))
	}
}

func TestRootHash(t *testing.T) {
	cs := NewChainStore()
	cs.Add(10, []byte("a"))
	cs.Add(11, []byte("b"))
	root := cs.RootHash()
	if len(root) != 64 {
		t.Errorf("root hash length = %d", len(root))
	}
	t.Logf("Root hash: %s", root[:16])
}

func TestRootHashEmpty(t *testing.T) {
	cs := NewChainStore()
	root := cs.RootHash()
	if root == "" {
		t.Error("empty root hash")
	}
}

func TestCount(t *testing.T) {
	cs := NewChainStore()
	cs.Add(10, []byte("a"))
	cs.Add(11, []byte("b"))
	cs.Add(12, []byte("c"))

	if cs.Count() != 3 {
		t.Errorf("count = %d", cs.Count())
	}
}

// ─── Anchoring tests ────────────────────────────────────────

func TestNewAnchoringManager(t *testing.T) {
	cs := NewChainStore()
	am := NewAnchoringManager(nil, cs)
	if am == nil {
		t.Fatal("NewAnchoringManager returned nil")
	}
}

func TestAnchor(t *testing.T) {
	cs := NewChainStore()
	cs.Add(10, []byte("test"))

	am := NewAnchoringManager(&AnchorConfig{
		EnableKmsg:     false,
		EnableRemote:   false,
		AnchorInterval: time.Minute,
	}, cs)

	am.anchor()
	anchors := am.Anchors()
	if len(anchors) != 0 {
		t.Log("anchor recorded via fallback")
	}
}

func TestStartStop(t *testing.T) {
	cs := NewChainStore()
	am := NewAnchoringManager(nil, cs)
	am.Start()
	time.Sleep(50 * time.Millisecond)
	am.Stop()
}

func TestLatestAnchor(t *testing.T) {
	cs := NewChainStore()
	am := NewAnchoringManager(nil, cs)

	// Manually add an anchor
	am.mu.Lock()
	am.anchors = append(am.anchors, AnchorRecord{
		Timestamp: time.Now(), RootHash: "abc123", ChainLen: 5,
	})
	am.mu.Unlock()

	latest := am.LatestAnchor()
	if latest == nil {
		t.Fatal("nil latest anchor")
	}
	if latest.RootHash != "abc123" {
		t.Errorf("hash = %s", latest.RootHash)
	}
}

// ─── Verify tests ───────────────────────────────────────────

func TestVerifyEmptyChain(t *testing.T) {
	cs := NewChainStore()
	report := cs.Verify()
	if !report.ChainIntact {
		t.Error("empty chain should be intact")
	}
}

func TestVerifyValidChain(t *testing.T) {
	cs := NewChainStore()
	for i := 0; i < 5; i++ {
		cs.Add(uint32(i), []byte{byte(i)})
	}

	report := cs.Verify()
	if !report.ChainIntact {
		t.Error("valid chain should be intact")
	}
	if report.TotalRecords != 5 {
		t.Errorf("records = %d", report.TotalRecords)
	}
	t.Logf("Verify: %s", report.Summary())
}

func TestVerifyDetectsTampering(t *testing.T) {
	cs := NewChainStore()
	cs.Add(10, []byte("event1"))
	cs.Add(11, []byte("event2"))

	// Tamper with a record
	cs.mu.Lock()
	cs.records[0].ChainHash = "tampered"
	cs.mu.Unlock()

	report := cs.Verify()
	if report.ChainIntact {
		t.Error("should detect tampering")
	}
	if len(report.Issues) == 0 {
		t.Error("should have issues")
	}
	t.Logf("Tamper detection: %s", report.Summary())
}

func TestVerifyDetectsGap(t *testing.T) {
	cs := NewChainStore()
	r1 := cs.Add(10, []byte("event1"))
	r2 := cs.Add(11, []byte("event2"))

	// Break the chain linkage
	cs.mu.Lock()
	cs.records[1].PrevHash = "wrong_hash"
	cs.mu.Unlock()

	report := cs.Verify()
	if report.Gaps != 1 {
		t.Errorf("gaps = %d", report.Gaps)
	}
	_ = r1
	_ = r2
}

func TestTruncate(t *testing.T) {
	if truncate("abcdefghijklmnop", 8) != "abcdefgh..." {
		t.Errorf("truncate = %s", truncate("abcdefghijklmnop", 8))
	}
	if truncate("short", 16) != "short" {
		t.Errorf("short = %s", truncate("short", 16))
	}
}

// ─── Integration test ───────────────────────────────────────

func TestChainIntegration(t *testing.T) {
	t.Log("=== Chain Integrity Integration ===")

	// 1. Build hash chain
	cs := NewChainStore()
	for i := 0; i < 100; i++ {
		cs.Add(uint32(i), []byte(fmt.Sprintf("event-%d", i)))
	}
	t.Logf("Chain built: %d records", cs.Count())
	t.Logf("Root hash: %s", cs.RootHash()[:16])

	// 2. Verify integrity
	report := cs.Verify()
	t.Logf("Verify: chain=%v hmac=%v gaps=%d",
		report.ChainIntact, report.HMACValid, report.Gaps)
	if !report.ChainIntact {
		t.Error("chain should be intact")
	}

	// 3. Anchoring
	am := NewAnchoringManager(&AnchorConfig{
		EnableKmsg: false, EnableRemote: false,
	}, cs)
	am.anchor()
	anchors := am.Anchors()
	t.Logf("Anchors: %d", len(anchors))

	// 4. Verify individual records
	for _, rec := range cs.records {
		if !cs.VerifyRecord(rec) {
			t.Errorf("record %d failed verification", rec.Index)
		}
	}

	t.Log("Chain integrity integration OK")
}
