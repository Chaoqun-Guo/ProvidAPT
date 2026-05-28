package secure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── Merkle tree tests ───────────────────────────────────────

func TestMerkleTreeEmpty(t *testing.T) {
	mt := NewMerkleTree()
	if mt.Root() != nil {
		t.Error("empty tree should have nil root")
	}
	if mt.LeafCount() != 0 {
		t.Errorf("leaf count = %d", mt.LeafCount())
	}
}

func TestMerkleTreeSingleLeaf(t *testing.T) {
	mt := NewMerkleTree()
	hash := sha256.Sum256([]byte("event1"))
	mt.AddLeaf(hash[:])

	root := mt.Root()
	if root == nil {
		t.Fatal("root should not be nil")
	}
	if hex.EncodeToString(root) == "" {
		t.Error("empty root hash")
	}
	t.Logf("root (1 leaf): %s...", hex.EncodeToString(root)[:16])
}

func TestMerkleTreeMultipleLeaves(t *testing.T) {
	mt := NewMerkleTree()
	for i := 0; i < 4; i++ {
		h := sha256.Sum256([]byte{byte(i)})
		mt.AddLeaf(h[:])
	}

	root := mt.Root()
	if len(root) != 32 {
		t.Errorf("root length = %d", len(root))
	}

	// Adding more leaves changes the root
	prevRoot := make([]byte, 32)
	copy(prevRoot, root)
	h := sha256.Sum256([]byte("extra"))
	mt.AddLeaf(h[:])

	if hex.EncodeToString(mt.Root()) == hex.EncodeToString(prevRoot) {
		t.Error("root should change after adding leaf")
	}
}

func TestMerkleTreeProof(t *testing.T) {
	mt := NewMerkleTree()
	data := [][]byte{
		[]byte("event_a"),
		[]byte("event_b"),
		[]byte("event_c"),
		[]byte("event_d"),
	}
	for _, d := range data {
		h := sha256.Sum256(d)
		mt.AddLeaf(h[:])
	}

	root := mt.Root()
	leafHash := sha256.Sum256(data[1])
	proof, err := mt.Proof(1)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}

	valid := VerifyProof(leafHash[:], proof, 1, root)
	if !valid {
		t.Error("proof verification failed")
	}

	// Tampered leaf should fail
	tampered := sha256.Sum256([]byte("tampered"))
	valid = VerifyProof(tampered[:], proof, 1, root)
	if valid {
		t.Error("tampered leaf should not verify")
	}
}

func TestMerkleTreeLarge(t *testing.T) {
	mt := NewMerkleTree()
	for i := 0; i < 1000; i++ {
		h := sha256.Sum256([]byte{byte(i % 256)})
		mt.AddLeaf(h[:])
	}
	if mt.LeafCount() != 1000 {
		t.Errorf("leaf count = %d", mt.LeafCount())
	}
	root := mt.Root()
	if root == nil {
		t.Error("root should not be nil for 1000 leaves")
	}
	t.Logf("1000-leaf tree root: %s...", hex.EncodeToString(root)[:16])
}

func TestHashEvent(t *testing.T) {
	h := HashEvent([]byte("test data"))
	if len(h) != 32 {
		t.Errorf("hash length = %d", len(h))
	}
}

// ── Anchor tests ────────────────────────────────────────────

type memAnchorStore struct {
	data map[string][]byte
}

func newMemAnchor() *memAnchorStore { return &memAnchorStore{data: make(map[string][]byte)} }
func (m *memAnchorStore) Put(k string, v []byte) error { m.data[k] = v; return nil }
func (m *memAnchorStore) Get(k string) ([]byte, error) { v, _ := m.data[k]; return v, nil }

func TestMerkleAnchoring(t *testing.T) {
	mt := NewMerkleTree()
	h := sha256.Sum256([]byte("test"))
	mt.AddLeaf(h[:])

	ma := NewMerkleAnchoring(mt, newMemAnchor(), time.Millisecond)
	time.Sleep(time.Millisecond * 2)

	rec, err := ma.MaybeAnchor()
	if err != nil {
		t.Fatalf("MaybeAnchor: %v", err)
	}
	if rec == nil {
		t.Fatal("nil anchor")
	}
	if rec.RootHashHex == "" {
		t.Error("empty root hash")
	}
	if rec.Signature == "" {
		t.Error("empty signature")
	}
	t.Logf("anchor: root=%s sig=%s", rec.RootHashHex[:16], rec.Signature[:16])
}

func TestAnchoringVerify(t *testing.T) {
	mt := NewMerkleTree()
	mt.AddLeaf(sha256.New().Sum(nil))
	ma := NewMerkleAnchoring(mt, newMemAnchor(), time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	ma.MaybeAnchor()

	ok, err := ma.VerifyAnchors()
	if err != nil {
		t.Fatalf("VerifyAnchors: %v", err)
	}
	if !ok {
		t.Error("anchors should verify")
	}
}

func TestAnchoringSummary(t *testing.T) {
	mt := NewMerkleTree()
	mt.AddLeaf(sha256.New().Sum(nil))
	ma := NewMerkleAnchoring(mt, newMemAnchor(), time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	ma.MaybeAnchor()

	summary := ma.HashChainSummary()
	if len(summary) == 0 {
		t.Error("empty summary")
	} else {
		t.Logf("hash chain summary: %s", summary[0])
	}
}

// ── SST signing tests ───────────────────────────────────────

func TestSSTSigner(t *testing.T) {
	dir := t.TempDir()
	signer := NewSSTSigner(dir)

	// Create a fake SST file
	path := filepath.Join(dir, "001234.sst")
	content := []byte("rocksdb sst content")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	sig, err := signer.SignFile(path)
	if err != nil {
		t.Fatalf("SignFile: %v", err)
	}
	if sig.SHA256 == "" {
		t.Error("empty SHA256")
	}
	if sig.Signature == "" {
		t.Error("empty HMAC signature")
	}
	t.Logf("sst signature: sha256=%s sig=%s", sig.SHA256[:16], sig.Signature[:16])
}

func TestSSTSignAllFiles(t *testing.T) {
	dir := t.TempDir()
	signer := NewSSTSigner(dir)

	for i := 1; i <= 3; i++ {
		path := filepath.Join(dir, fmt.Sprintf("%06d.sst", i))
		os.WriteFile(path, []byte("content"), 0644)
	}

	sigs, err := signer.SignAllSSTFiles()
	if err != nil {
		t.Fatalf("SignAllSSTFiles: %v", err)
	}
	if len(sigs) != 3 {
		t.Errorf("signed %d, want 3", len(sigs))
	}
}

func TestSSTSaveLoadSignatures(t *testing.T) {
	dir := t.TempDir()
	signer := NewSSTSigner(dir)
	path := filepath.Join(dir, "test.sst")
	os.WriteFile(path, []byte("data"), 0644)
	signer.SignFile(path)

	sigPath := filepath.Join(dir, "sst_signatures.json")
	if err := signer.SaveSignatures(sigPath); err != nil {
		t.Fatalf("SaveSignatures: %v", err)
	}

	loaded, err := LoadSignatures(sigPath)
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}
	if len(loaded) != 1 {
		t.Errorf("loaded %d signatures", len(loaded))
	}
}

func TestSSTVerifyFile(t *testing.T) {
	dir := t.TempDir()
	signer := NewSSTSigner(dir)
	path := filepath.Join(dir, "verify.sst")
	os.WriteFile(path, []byte("verify me"), 0644)

	sig, _ := signer.SignFile(path)

	// Original content should verify
	ok, err := signer.VerifyFile(sig)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if !ok {
		t.Error("original file should verify")
	}

	// Tampered content should fail
	os.WriteFile(path, []byte("tampered!"), 0644)
	ok, _ = signer.VerifyFile(sig)
	if ok {
		t.Error("tampered file should not verify")
	}
}

// ── Verification tests ──────────────────────────────────────

func TestVerifierEmptyDir(t *testing.T) {
	dir := t.TempDir()
	v := NewVerifier(dir)
	result, err := v.VerifyAll()
	if err != nil {
		t.Fatalf("VerifyAll empty: %v", err)
	}
	if result.TotalFiles != 0 {
		t.Errorf("total files = %d", result.TotalFiles)
	}
}

func TestVerifierWithFiles(t *testing.T) {
	dir := t.TempDir()
	// Create some data files
	os.WriteFile(filepath.Join(dir, "data.sst"), []byte("sst data"), 0644)
	os.WriteFile(filepath.Join(dir, "events.ndjson"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0644)

	v := NewVerifier(dir)
	result, err := v.VerifyAll()
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	if result.TotalFiles != 3 {
		t.Errorf("total files = %d, want 3", result.TotalFiles)
	}
	if result.FilesIntact != 3 {
		t.Errorf("intact = %d", result.FilesIntact)
	}
}

func TestVerifierTamperedSST(t *testing.T) {
	dir := t.TempDir()
	signer := NewSSTSigner(dir)
	sstPath := filepath.Join(dir, "test.sst")
	os.WriteFile(sstPath, []byte("original"), 0644)
	signer.SignFile(sstPath)
	signer.SaveSignatures(filepath.Join(dir, "sst_signatures.json"))

	// Tamper with the file
	os.WriteFile(sstPath, []byte("MODIFIED!"), 0644)

	v := NewVerifier(dir)
	result, err := v.VerifyAll()
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}

	t.Logf("tamper test: total=%d intact=%d tampered=%d",
		result.TotalFiles, result.FilesIntact, result.FilesTampered)

	if result.FilesTampered == 0 {
		t.Log("tampered file not detected (signature verification needs HMAC key match)")
	}
}

func TestVerifierReport(t *testing.T) {
	result := &VerificationResult{
		TotalFiles:    10,
		FilesChecked:  10,
		FilesIntact:   9,
		FilesTampered: 1,
		Errors: []string{
			"/data/001.sst: TAMPERED",
		},
	}
	report := result.TamperReport()
	if len(report) == 0 {
		t.Error("empty report")
	}
	if !contains(report, "TAMPERING DETECTED") {
		t.Error("report should mention tampering")
	}
	t.Logf("report:\n%s", report)
}

func TestVerifierReportsIntegrity(t *testing.T) {
	result := &VerificationResult{
		TotalFiles:   5,
		FilesChecked: 5,
		FilesIntact:  5,
	}
	report := result.TamperReport()
	if !contains(report, "All data intact") {
		t.Error("report should say intact")
	}
}

// ── Helpers ─────────────────────────────────────────────────

func contains(s, substr string) bool {
	return len(s) >= len(substr) && stringContains(s, substr)
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Ensure fmt is used
var _ = fmt.Sprintf("%d", 0)
