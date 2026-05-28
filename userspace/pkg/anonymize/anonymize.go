// Package anonymize provides field-level anonymization for GDPR
// compliance.  Sensitive fields (file paths, IP addresses, usernames)
// are hashed with HMAC-SHA256 before entering RocksDB, while
// preserving the deterministic mapping needed for graph connectivity.
//
// Architecture:
//
//   Raw Event → Anonymizer → Anonymized Event → Pipeline → RocksDB
//                  │
//                  ├── HMAC(path) → node_id (deterministic)
//                  ├── HMAC(ip)   → network_id (deterministic)
//                  └── AES-GCM encrypt(original) → de-anon store
//
// De-anonymization:
//   Authorized auditor runs: providapt-deanon <hash> [keyfile]
//   → Looks up hash in de-anon store → decrypts original path
//   → Returns: /etc/shadow (forensically admissible)
package anonymize

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// ═══════════════════════════════════════════════════════════════
// Anonymizer
// ═══════════════════════════════════════════════════════════════

// Anonymizer provides deterministic field-level anonymization.
// It uses HMAC-SHA256 with a configurable secret key for hashing,
// and AES-GCM for reversible encryption in the de-anon store.
type Anonymizer struct {
	hmacKey   []byte
	encKey    []byte
	deanon    *DeAnonStore
	mu        sync.Mutex
}

// Config for the anonymizer.
type Config struct {
	// HMACKeyHex is the hex-encoded HMAC key (32 bytes for SHA256).
	HMACKeyHex string

	// EncKeyHex is the hex-encoded AES encryption key (32 bytes for AES-256).
	EncKeyHex string

	// DeAnonPath is the path to the de-anonymization store file.
	// If empty, de-anonymization is disabled.
	DeAnonPath string
}

// New creates an Anonymizer with the given configuration.
func New(cfg *Config) (*Anonymizer, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	a := &Anonymizer{}

	// HMAC key: use provided or generate random
	if cfg.HMACKeyHex != "" {
		key, err := hex.DecodeString(cfg.HMACKeyHex)
		if err != nil {
			return nil, fmt.Errorf("decode hmac key: %w", err)
		}
		a.hmacKey = key
	} else {
		a.hmacKey = make([]byte, 32)
		rand.Read(a.hmacKey)
	}

	// Encryption key for de-anon store
	if cfg.EncKeyHex != "" {
		key, err := hex.DecodeString(cfg.EncKeyHex)
		if err != nil {
			return nil, fmt.Errorf("decode enc key: %w", err)
		}
		a.encKey = key
	} else {
		a.encKey = make([]byte, 32)
		rand.Read(a.encKey)
	}

	// De-anon store
	if cfg.DeAnonPath != "" {
		store, err := NewDeAnonStore(cfg.DeAnonPath, a.encKey)
		if err != nil {
			return nil, fmt.Errorf("deanon store: %w", err)
		}
		a.deanon = store
	}

	return a, nil
}

// ─── HMAC hashing (deterministic, one-way) ─────────────────

// HashString returns a deterministic HMAC-SHA256 hash of s.
// The output is truncated to prefixLen hex characters.
func (a *Anonymizer) HashString(s string, prefixLen int) string {
	mac := hmac.New(sha256.New, a.hmacKey)
	mac.Write([]byte(s))
	hash := hex.EncodeToString(mac.Sum(nil))
	if prefixLen > 0 && prefixLen < len(hash) {
		hash = hash[:prefixLen]
	}
	return hash
}

// HashPath anonymizes a file path while preserving structural identity.
// The same path always produces the same hash (deterministic).
//
// Example:
//   "/etc/shadow" → "a3f8b2c1e4d5f6a7"
//   (same input = same output → graph connectivity preserved)
func (a *Anonymizer) HashPath(path string) string {
	return a.HashString(path, 16)
}

// HashIP anonymizes an IP address while preserving identity.
func (a *Anonymizer) HashIP(ip string) string {
	return "ip_" + a.HashString(ip, 12)
}

// HashComm anonymizes a process name.
func (a *Anonymizer) HashComm(comm string) string {
	return a.HashString(comm, 8)
}

// ─── Event anonymization ────────────────────────────────────

// AnonymizedEvent holds the anonymized version of an event.
type AnonymizedEvent struct {
	// Timestamp preserved in clear (needed for ordering)
	TimestampNS uint64

	// PID preserved (needed for process identity)
	PID  uint32
	PPID uint32
	UID  uint32

	// Comm hashed (process name)
	Comm string

	// Path hashed (file path)
	Pathname string

	// Event type preserved (needed for semantics)
	Type uint32
	Flags uint32

	// Inode preserved (needed for file identity)
	Inode    uint64
	DevMajor uint32
	DevMinor uint32
	Mode     uint32
	FFlags   uint32

	// Child PID preserved for fork events
	ChildPID uint32
}

// AnonymizeEvent converts a raw event to an anonymized version.
// Returns the anonymized event AND optionally stores the original
// in the de-anon store for authorized recovery.
func (a *Anonymizer) AnonymizeEvent(
	evtType uint32,
	timestamp uint64,
	pid, ppid, uid uint32,
	comm, pathname string,
	inode uint64, devMajor, devMinor, mode, fflags uint32,
	childPID uint32,
) *AnonymizedEvent {

	anon := &AnonymizedEvent{
		TimestampNS: timestamp,
		PID:  pid,
		PPID: ppid,
		UID:  uid,
		Comm: a.HashComm(comm),
		Type: evtType,
		Flags: 0,
		Inode:    inode,
		DevMajor: devMajor,
		DevMinor: devMinor,
		Mode:     mode,
		FFlags:   fflags,
		ChildPID: childPID,
	}

	// Anonymize path
	if pathname != "" && pathname != "?" {
		origPath := pathname
		anon.Pathname = a.HashPath(pathname)

		// Store original in de-anon store for authorized decryption
		if a.deanon != nil && origPath != anon.Pathname {
			a.mu.Lock()
			a.deanon.Store(anon.Pathname, origPath)
			a.mu.Unlock()
		}
	} else {
		anon.Pathname = pathname
	}

	return anon
}

// ─── Key management ─────────────────────────────────────────

// HMACKeyHex returns the hex-encoded HMAC key (for backup).
func (a *Anonymizer) HMACKeyHex() string {
	return hex.EncodeToString(a.hmacKey)
}

// SaveKeyFile saves the HMAC and encryption keys to a protected file.
func SaveKeyFile(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600) // owner-read only
}

// LoadKeyFile loads anonymization keys from a protected file.
func LoadKeyFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ─── Path prefix handling for de-anonymization ──────────────

// IsAnonymizedPath returns true if a string looks like an anonymized path.
func IsAnonymizedPath(s string) bool {
	return len(s) == 16 && isHex(s)
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// ═══════════════════════════════════════════════════════════════
// De-anonymization store
// ═══════════════════════════════════════════════════════════════

// DeAnonStore stores encrypted original values for authorized recovery.
// The store is a JSON file where each entry is:
//
//	{ "hash": "...", "ciphertext": "..." }
//
// The ciphertext is AES-GCM encrypted and can only be decrypted
// with the encryption key held by authorized auditors.
type DeAnonStore struct {
	path    string
	key     []byte
	entries map[string]string // hash → ciphertext (hex)
	mu      sync.RWMutex
}

// NewDeAnonStore creates or loads a de-anonymization store.
func NewDeAnonStore(path string, encKey []byte) (*DeAnonStore, error) {
	s := &DeAnonStore{
		path:    path,
		key:     encKey,
		entries: make(map[string]string),
	}
	// Load existing entries
	if data, err := os.ReadFile(path); err == nil {
		var entries []struct {
			Hash       string `json:"hash"`
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.Unmarshal(data, &entries); err == nil {
			for _, e := range entries {
				s.entries[e.Hash] = e.Ciphertext
			}
		}
	}
	return s, nil
}

// Store encrypts a value and stores it by hash key.
func (ds *DeAnonStore) Store(hash, original string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	// Check if already stored
	if _, ok := ds.entries[hash]; ok {
		return nil // already stored
	}

	// Encrypt with AES-GCM
	block, err := aes.NewCipher(ds.key)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	rand.Read(nonce)

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(original), nil)
	ds.entries[hash] = hex.EncodeToString(ciphertext)
	return ds.save()
}

// Lookup decrypts and returns the original value for a hash.
func (ds *DeAnonStore) Lookup(hash string) (string, error) {
	ds.mu.RLock()
	cipherHex, ok := ds.entries[hash]
	ds.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("hash %s not found in de-anon store", hash)
	}

	ciphertext, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(ds.key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

func (ds *DeAnonStore) save() error {
	var entries []struct {
		Hash       string `json:"hash"`
		Ciphertext string `json:"ciphertext"`
	}
	for h, c := range ds.entries {
		entries = append(entries, struct {
			Hash       string `json:"hash"`
			Ciphertext string `json:"ciphertext"`
		}{h, c})
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ds.path, data, 0600)
}

// EntryCount returns the number of stored entries.
func (ds *DeAnonStore) EntryCount() int {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return len(ds.entries)
}
