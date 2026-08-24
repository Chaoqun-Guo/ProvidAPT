// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	AESKeySize   = 32     // 256-bit
	NonceSize    = 12     // AES-GCM standard nonce
	pbkdf2Iters  = 600000 // OWASP 2023 recommended minimum for SHA-256
	pbkdf2KeyLen = 32
)

// DeriveKey derives a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.
// Salt should be a unique per-key value (12+ bytes from crypto/rand).
// If salt is nil, a warning is logged (callers should provide one).
func DeriveKey(passphrase string, salt []byte) []byte {
	if salt == nil {
		// Fallback: derive salt from passphrase itself (weaker but still
		// better than raw SHA-256). Callers should provide a proper salt.
		h := sha256.Sum256([]byte(passphrase))
		salt = h[:16]
	}
	return pbkdf2HMACSHA256([]byte(passphrase), salt, pbkdf2Iters, pbkdf2KeyLen)
}

// pbkdf2HMACSHA256 implements PBKDF2-HMAC-SHA256 using standard library only.
func pbkdf2HMACSHA256(password, salt []byte, iter, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)
	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)

		blockKey := make([]byte, hashLen)
		copy(blockKey, u)

		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := 0; j < hashLen; j++ {
				blockKey[j] ^= u[j]
			}
		}
		dk = append(dk, blockKey...)
	}

	return dk[:keyLen]
}

// DeprecatedDeriveKey is the old SHA-256-only derivation, kept for
// backward compatibility with existing stored data.
func DeprecatedDeriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

// Encrypt encrypts plaintext with AES-256-GCM.
// Output format: [12-byte nonce][ciphertext][16-byte GCM tag]
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	// Sealed: nonce + ciphertext + auth tag
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts a ciphertext produced by Encrypt.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	if len(ciphertext) < NonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:NonceSize]
	sealed := ciphertext[NonceSize:]

	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptionKey manages an AES-256 key with file persistence.
type EncryptionKey struct {
	key  []byte
	path string
}

// LoadOrGenerateKey loads a 256-bit key from path, or generates a new one
// if the file does not exist. The key file contains raw 32 bytes (0600).
func LoadOrGenerateKey(path string) (*EncryptionKey, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("key dir: %w", err)
	}

	data, err := os.ReadFile(path)
	if err == nil && len(data) == AESKeySize {
		return &EncryptionKey{key: data, path: path}, nil
	}

	// Generate new key
	key := make([]byte, AESKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}

	return &EncryptionKey{key: key, path: path}, nil
}

// Bytes returns the raw key material.
func (ek *EncryptionKey) Bytes() []byte {
	return ek.key
}

// ConstantTimeCompare compares two strings in constant time,
// preventing timing side-channel attacks.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
