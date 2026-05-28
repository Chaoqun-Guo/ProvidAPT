package secure

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// SST file signing
//
// After RocksDB compaction produces new SST files, we compute
// SHA256 hashes and HMAC signatures to detect offline tampering.
// ═══════════════════════════════════════════════════════════════

// SSTSignature records the hash and HMAC for a single SST file.
type SSTSignature struct {
	FilePath   string `json:"file_path"`
	FileSize   int64  `json:"file_size"`
	SHA256     string `json:"sha256"`     // hex
	Timestamp  int64  `json:"timestamp_ns"`
	Signature  string `json:"signature"`  // HMAC-SHA256 hex
}

// SSTSigner manages SST file signing.
type SSTSigner struct {
	storeDir string
	hmacKey  []byte
	sigs     []SSTSignature
}

// NewSSTSigner creates an SST signer for the given store directory.
func NewSSTSigner(storeDir string) *SSTSigner {
	key := make([]byte, 32)
	rand.Read(key) // from merkle.go import — crypto/rand
	return &SSTSigner{
		storeDir: storeDir,
		hmacKey:  key,
	}
}

// SignFile computes a signature for a single SST file.
func (ss *SSTSigner) SignFile(path string) (*SSTSignature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	hash := sha256.Sum256(data)
	hexHash := hex.EncodeToString(hash[:])

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	sig := &SSTSignature{
		FilePath:  path,
		FileSize:  info.Size(),
		SHA256:    hexHash,
		Timestamp: time.Now().UnixNano(),
	}

	// HMAC sign
	mac := hmac.New(sha256.New, ss.hmacKey)
	mac.Write([]byte(sig.FilePath))
	mac.Write(hash[:])
	mac.Write([]byte(fmt.Sprintf("%d", sig.FileSize)))
	sig.Signature = hex.EncodeToString(mac.Sum(nil))

	ss.sigs = append(ss.sigs, *sig)
	return sig, nil
}

// SignAllSSTFiles scans the store directory and signs all .sst files.
func (ss *SSTSigner) SignAllSSTFiles() ([]SSTSignature, error) {
	var signed []SSTSignature

	err := filepath.Walk(ss.storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".sst" {
			return nil
		}
		sig, err := ss.SignFile(path)
		if err != nil {
			return fmt.Errorf("sign %s: %w", path, err)
		}
		signed = append(signed, *sig)
		return nil
	})

	if err != nil {
		return signed, err
	}
	ss.sigs = append(ss.sigs, signed...)
	return signed, nil
}

// SaveSignatures persists the signature list to a JSON file.
func (ss *SSTSigner) SaveSignatures(path string) error {
	data, _ := json.MarshalIndent(ss.sigs, "", "  ")
	return os.WriteFile(path, data, 0400)
}

// LoadSignatures reads SST signatures from a JSON file.
func LoadSignatures(path string) ([]SSTSignature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sigs []SSTSignature
	if err := json.Unmarshal(data, &sigs); err != nil {
		return nil, err
	}
	return sigs, nil
}

// VerifyFile checks if a file's current hash matches its signature.
// Returns true if the file is intact.
func (ss *SSTSigner) VerifyFile(sig *SSTSignature) (bool, error) {
	data, err := os.ReadFile(sig.FilePath)
	if err != nil {
		return false, fmt.Errorf("read: %w", err)
	}

	// Check SHA256
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != sig.SHA256 {
		return false, nil
	}

	// Check HMAC signature
	expected := ss.computeHMAC(sig.FilePath, hash[:], sig.FileSize)
	return hmac.Equal([]byte(sig.Signature), []byte(expected)), nil
}

func (ss *SSTSigner) computeHMAC(path string, fileHash []byte, size int64) string {
	mac := hmac.New(sha256.New, ss.hmacKey)
	mac.Write([]byte(path))
	mac.Write(fileHash)
	mac.Write([]byte(fmt.Sprintf("%d", size)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Stats returns signing statistics.
func (ss *SSTSigner) Stats() map[string]interface{} {
	return map[string]interface{}{
		"files_signed": len(ss.sigs),
		"store_dir":    ss.storeDir,
	}
}
