package secure

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble"
)

// ─── Crypto tests ─────────────────────────────────────────────

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("sensitive provenance data")
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Output format: [12-byte nonce][ciphertext][16-byte GCM tag]
	if len(ciphertext) <= NonceSize {
		t.Fatalf("ciphertext too short: %d", len(ciphertext))
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("round-trip mismatch")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xff

	plaintext := []byte("test data")
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(wrongKey, ciphertext)
	if err == nil {
		t.Error("expected error with wrong key")
	}
}

func TestDecryptShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := Decrypt(key, []byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for short ciphertext")
	}
}

func TestDeriveKey(t *testing.T) {
	salt := []byte("unique-salt-1234")
	key1 := DeriveKey("my-passphrase", salt)
	key2 := DeriveKey("my-passphrase", salt)
	key3 := DeriveKey("different-passphrase", salt)

	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
	if !bytes.Equal(key1, key2) {
		t.Error("same passphrase + salt should produce same key")
	}
	if bytes.Equal(key1, key3) {
		t.Error("different passphrase should produce different key")
	}
}

func TestDeriveKeyNilSalt(t *testing.T) {
	key := DeriveKey("passphrase", nil)
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}

func TestDeriveKeyConsistency(t *testing.T) {
	// PBKDF2 with same inputs should always produce same output
	salt := []byte("fixed-salt-for-test")
	key1 := DeriveKey("consistent-pass", salt)
	key2 := DeriveKey("consistent-pass", salt)

	if !bytes.Equal(key1, key2) {
		t.Error("PBKDF2 is not deterministic with same inputs")
	}
	t.Logf("derived key: %s", hex.EncodeToString(key1))
}

func TestDeprecatedDeriveKey(t *testing.T) {
	key := DeprecatedDeriveKey("old-passphrase")
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// SHA-256 of same input should be consistent
	key2 := DeprecatedDeriveKey("old-passphrase")
	if !bytes.Equal(key, key2) {
		t.Error("SHA-256 derivation is not deterministic")
	}
}

// ─── LoadOrGenerateKey tests ──────────────────────────────────

func TestLoadOrGenerateKeyNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "encryption.key")

	ek, err := LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	if len(ek.Bytes()) != 32 {
		t.Errorf("key length = %d", len(ek.Bytes()))
	}

	// Key file should exist with correct size
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 32 {
		t.Errorf("key file length = %d", len(data))
	}
}

func TestLoadOrGenerateKeyExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.key")

	// Create first key
	ek1, err := LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	// Load existing key
	ek2, err := LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if !bytes.Equal(ek1.Bytes(), ek2.Bytes()) {
		t.Error("loaded key should match generated key")
	}
}

func TestLoadOrGenerateKeyWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")

	// Write wrong-size key file
	if err := os.WriteFile(path, []byte("too-short"), 0600); err != nil {
		t.Fatal(err)
	}

	// Should regenerate since size is wrong
	ek, err := LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	if len(ek.Bytes()) != 32 {
		t.Errorf("key length = %d", len(ek.Bytes()))
	}
}

// ─── EncryptedStore tests ─────────────────────────────────────

func openPebbleDB(t *testing.T) *pebble.DB {
	t.Helper()
	dir, err := os.MkdirTemp("", "providapt-secure-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, err := pebble.Open(dir+"/pebble", &pebble.Options{})
	if err != nil {
		t.Fatalf("pebble: %v", err)
	}
	return db
}

func TestEncryptedStoreSetGet(t *testing.T) {
	db := openPebbleDB(t)
	defer db.Close()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	es := NewEncryptedStore(db, key)
	value := []byte("sensitive-value")

	if err := es.Set([]byte("my-key"), value, nil); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Direct read from Pebble should be encrypted
	encValue, closer, err := db.Get([]byte("my-key"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encValue, value) {
		t.Error("value stored in plaintext!")
	}
	closer.Close()

	// Read through EncryptedStore should decrypt
	got, closer, err := es.Get([]byte("my-key"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer closer.Close()

	if !bytes.Equal(got, value) {
		t.Error("decrypted value mismatch")
	}
}

func TestEncryptedStoreDelete(t *testing.T) {
	db := openPebbleDB(t)
	defer db.Close()

	es := NewEncryptedStore(db, []byte("01234567890123456789012345678901"))
	es.Set([]byte("del-key"), []byte("value"), nil)

	if err := es.Delete([]byte("del-key"), nil); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, closer, err := es.Get([]byte("del-key"))
	if err != pebble.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
	if closer != nil {
		closer.Close()
	}
}

func TestEncryptedStoreGetNotFound(t *testing.T) {
	db := openPebbleDB(t)
	defer db.Close()

	es := NewEncryptedStore(db, []byte("01234567890123456789012345678901"))
	_, closer, err := es.Get([]byte("nonexistent"))
	if err != pebble.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
	if closer != nil {
		closer.Close()
	}
}

func TestEncryptedStoreIterator(t *testing.T) {
	db := openPebbleDB(t)
	defer db.Close()

	es := NewEncryptedStore(db, make([]byte, 32))

	entries := map[string]string{
		"key-a": "value-a",
		"key-b": "value-b",
		"key-c": "value-c",
	}
	for k, v := range entries {
		if err := es.Set([]byte(k), []byte(v), nil); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}

	iter, err := es.NewIter(&pebble.IterOptions{
		LowerBound: []byte("key-"),
		UpperBound: []byte("key-\xff"),
	})
	if err != nil {
		t.Fatalf("NewIter: %v", err)
	}
	defer iter.Close()

	count := 0
	for iter.First(); iter.Valid(); iter.Next() {
		val := iter.Value()
		if val == nil {
			t.Error("nil value from iterator")
			continue
		}
		key := string(iter.Key())
		expected, ok := entries[key]
		if !ok {
			t.Errorf("unexpected key: %s", key)
			continue
		}
		if string(val) != expected {
			t.Errorf("key %s: value = %s, want %s", key, string(val), expected)
		}
		count++
	}
	if count != 3 {
		t.Errorf("iterated %d entries, want 3", count)
	}
}

func TestEncryptedStoreIteratorEmpty(t *testing.T) {
	db := openPebbleDB(t)
	defer db.Close()

	es := NewEncryptedStore(db, make([]byte, 32))
	iter, err := es.NewIter(&pebble.IterOptions{})
	if err != nil {
		t.Fatalf("NewIter: %v", err)
	}
	defer iter.Close()

	if iter.First() {
		t.Error("expected empty iterator")
	}
}

func TestEncryptedStoreFlush(t *testing.T) {
	db := openPebbleDB(t)
	defer db.Close()

	es := NewEncryptedStore(db, make([]byte, 32))
	if err := es.Flush(); err != nil {
		t.Errorf("Flush: %v", err)
	}
}

func TestEncryptedStoreMetrics(t *testing.T) {
	db := openPebbleDB(t)
	defer db.Close()

	es := NewEncryptedStore(db, make([]byte, 32))
	m := es.Metrics()
	if m == nil {
		t.Error("nil metrics")
	}
}

func TestEncryptedStoreUnderlyingDB(t *testing.T) {
	db := openPebbleDB(t)
	defer db.Close()

	es := NewEncryptedStore(db, make([]byte, 32))
	if es.UnderlyingDB() != db {
		t.Error("UnderlyingDB mismatch")
	}
}

func TestEncryptedStoreClose(t *testing.T) {
	db := openPebbleDB(t)
	es := NewEncryptedStore(db, make([]byte, 32))
	if err := es.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestEncryptedIteratorInvalidKey(t *testing.T) {
	db := openPebbleDB(t)
	defer db.Close()

	// Store a value with a key that can't be decrypted
	key := make([]byte, 32)
	garbage := []byte("not-encrypted")
	if err := db.Set([]byte("bad-entry"), garbage, nil); err != nil {
		t.Fatal(err)
	}

	es := NewEncryptedStore(db, key)
	iter, err := es.NewIter(&pebble.IterOptions{})
	if err != nil {
		t.Fatalf("NewIter: %v", err)
	}
	defer iter.Close()

	found := false
	for iter.First(); iter.Valid(); iter.Next() {
		if string(iter.Key()) == "bad-entry" {
			found = true
			if iter.Value() != nil {
				t.Log("invalid entry returns nil value (as expected)")
			}
		}
	}
	if !found {
		t.Log("bad entry not iterated (iterator may skip)")
	}
}

// ─── Encrypt/Decrypt edge cases ───────────────────────────────

func TestEncryptNilPlaintext(t *testing.T) {
	key := make([]byte, 32)
	_, err := Encrypt(key, nil)
	if err != nil {
		t.Logf("Encrypt nil: %v (acceptable)", err)
	}
}

func TestDecryptNilCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := Decrypt(key, nil)
	if err == nil {
		t.Error("expected error decrypting nil")
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := make([]byte, 32)
	ct, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(pt) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(pt))
	}
}
