package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type signatureBundle struct {
	Type          string `json:"type"`
	Algorithm     string `json:"algorithm"`
	CreatedAt     string `json:"created_at"`
	MessageSHA256 string `json:"message_sha256"`
	PublicKey     string `json:"public_key"`
	Signature     string `json:"signature"`
}

func main() {
	in := flag.String("in", "", "file to sign")
	out := flag.String("out", "", "signature output path")
	keyPath := flag.String("key", "", "optional Ed25519 private key path")
	pubOut := flag.String("pub-out", "", "optional public key output path")
	flag.Parse()

	if strings.TrimSpace(*in) == "" || strings.TrimSpace(*out) == "" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: providapt-sign -in checksums.txt -out checksums.txt.sig [-key release.key] [-pub-out release.pub]")
		os.Exit(2)
	}

	message, err := os.ReadFile(*in)
	if err != nil {
		fail("read input", err)
	}
	priv, pub, err := loadOrCreateKey(*keyPath)
	if err != nil {
		fail("load key", err)
	}
	if strings.TrimSpace(*pubOut) != "" {
		if err := os.WriteFile(*pubOut, []byte(hex.EncodeToString(pub)+"\n"), 0644); err != nil {
			fail("write public key", err)
		}
	}

	sum := sha256.Sum256(message)
	bundle := signatureBundle{
		Type:          "providapt-ed25519-checksums-v1",
		Algorithm:     "ed25519",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		MessageSHA256: hex.EncodeToString(sum[:]),
		PublicKey:     hex.EncodeToString(pub),
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, message)),
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		fail("marshal signature", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(*out, data, 0644); err != nil {
		fail("write signature", err)
	}
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if strings.TrimSpace(path) != "" {
		if data, err := os.ReadFile(path); err == nil {
			key, err := decodePrivateKey(strings.TrimSpace(string(data)))
			if err != nil {
				return nil, nil, err
			}
			pub, ok := key.Public().(ed25519.PublicKey)
			if !ok {
				return nil, nil, fmt.Errorf("private key did not expose an Ed25519 public key")
			}
			return key, pub, nil
		} else if !os.IsNotExist(err) {
			return nil, nil, err
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(path) != "" {
		if err := os.WriteFile(path, []byte(hex.EncodeToString(priv)+"\n"), 0600); err != nil {
			return nil, nil, err
		}
	}
	return priv, pub, nil
}

func decodePrivateKey(raw string) (ed25519.PrivateKey, error) {
	if key, err := hex.DecodeString(raw); err == nil && len(key) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(key), nil
	}
	if key, err := base64.StdEncoding.DecodeString(raw); err == nil && len(key) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(key), nil
	}
	return nil, fmt.Errorf("private key must be hex or base64 encoded Ed25519 private key")
}

func fail(action string, err error) {
	_, _ = fmt.Fprintf(os.Stderr, "providapt-sign: %s: %v\n", action, err)
	os.Exit(1)
}
