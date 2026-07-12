// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package certauth provides automated CA and certificate generation for
// ProvidAPT's mTLS communication layer. All operations use crypto/x509
// from the Go standard library — zero external dependencies.
package certauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config controls certificate generation paths and parameters.
type Config struct {
	CADir      string // directory to store CA key + cert
	ServerDir  string // directory to store server key + cert
	ClientDir  string // directory to store client key + cert
	Org        string // organization name (default "ProvidAPT")
	ValidYears int    // validity in years (default 10)
	KeyBits    int    // RSA key bits (default 4096)
}

// defaults fills in zero-valued fields.
func (c *Config) defaults() {
	if c.Org == "" {
		c.Org = "ProvidAPT"
	}
	if c.ValidYears <= 0 {
		c.ValidYears = 10
	}
	if c.KeyBits <= 0 {
		c.KeyBits = 4096
	}
}

// CA holds the certificate authority key pair.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.PrivateKey
}

// Initialize generates a CA and server certificate. If CA files already exist,
// they are loaded and a new server certificate is signed. Returns the paths
// to the server cert, server key, and CA cert.
func Initialize(cfg *Config) (serverCertPath, serverKeyPath, caCertPath string, err error) {
	cfg.defaults()

	// Ensure directories
	for _, dir := range []string{cfg.CADir, cfg.ServerDir, cfg.ClientDir} {
		if dir != "" {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return "", "", "", fmt.Errorf("mkdir %s: %w", dir, err)
			}
		}
	}

	caCertPath = filepath.Join(cfg.CADir, "ca.crt")
	caKeyPath := filepath.Join(cfg.CADir, "ca.key")

	// Load or create CA
	var ca *CA
	if _, err := os.Stat(caCertPath); err == nil {
		ca, err = LoadCA(cfg)
		if err != nil {
			return "", "", "", fmt.Errorf("load CA: %w", err)
		}
	} else {
		caKey, err := rsa.GenerateKey(rand.Reader, cfg.KeyBits)
		if err != nil {
			return "", "", "", fmt.Errorf("generate CA key: %w", err)
		}

		caCert, err := createCACert(caKey, cfg)
		if err != nil {
			return "", "", "", fmt.Errorf("create CA cert: %w", err)
		}

		// Write CA key
		if err := writePrivateKey(caKeyPath, caKey); err != nil {
			return "", "", "", fmt.Errorf("write CA key: %w", err)
		}
		// Write CA cert
		if err := writeCert(caCertPath, caCert); err != nil {
			return "", "", "", fmt.Errorf("write CA cert: %w", err)
		}

		ca = &CA{Cert: caCert, Key: caKey}
	}

	// Generate server certificate
	serverCertFile := filepath.Join(cfg.ServerDir, "server.crt")
	serverKeyFile := filepath.Join(cfg.ServerDir, "server.key")

	serverCertPEM, serverKeyPEM, err := ca.CreateServerCert(cfg)
	if err != nil {
		return "", "", "", fmt.Errorf("create server cert: %w", err)
	}

	if err := os.WriteFile(serverCertFile, serverCertPEM, 0644); err != nil {
		return "", "", "", err
	}
	if err := os.WriteFile(serverKeyFile, serverKeyPEM, 0600); err != nil {
		return "", "", "", err
	}

	return serverCertFile, serverKeyFile, caCertPath, nil
}

// LoadCA loads an existing CA from the configured directory.
func LoadCA(cfg *Config) (*CA, error) {
	cfg.defaults()

	caCertPath := filepath.Join(cfg.CADir, "ca.crt")
	caKeyPath := filepath.Join(cfg.CADir, "ca.key")

	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block in CA key")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Fallback: try PKCS1
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA key: %w", err)
		}
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block in CA cert")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	return &CA{Cert: cert, Key: key}, nil
}

// CreateServerCert generates a server certificate signed by this CA.
func (ca *CA) CreateServerCert(cfg *Config) (certPEM, keyPEM []byte, err error) {
	cfg.defaults()

	key, err := rsa.GenerateKey(rand.Reader, cfg.KeyBits)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber(),
		Subject: pkix.Name{
			Organization: []string{cfg.Org},
			CommonName:   "providapt-server",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(cfg.ValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "providapt"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	hostname, _ := os.Hostname()
	if hostname != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, hostname)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return certPEM, keyPEM, nil
}

// CreateClientCert generates a client certificate signed by this CA.
func (ca *CA) CreateClientCert(cfg *Config, cn string) (certPEM, keyPEM []byte, err error) {
	cfg.defaults()

	key, err := rsa.GenerateKey(rand.Reader, cfg.KeyBits)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber(),
		Subject: pkix.Name{
			Organization: []string{cfg.Org},
			CommonName:   cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(cfg.ValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return certPEM, keyPEM, nil
}

// NeedsRotation checks whether a PEM certificate file expires within the given
// duration. Returns true if the cert is missing, expired, or expiring soon.
func NeedsRotation(certPath string, within time.Duration) (bool, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return true, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return true, fmt.Errorf("no PEM block in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, err
	}
	return time.Now().Add(within).After(cert.NotAfter), nil
}

// RotateServerCert signs a fresh server certificate with the existing CA and
// replaces certPath/keyPath after backing up old files with timestamp suffixes.
func RotateServerCert(cfg *Config, certPath, keyPath string) error {
	if cfg == nil {
		return fmt.Errorf("nil certauth config")
	}
	ca, err := LoadCA(cfg)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	certPEM, keyPEM, err := ca.CreateServerCert(cfg)
	if err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); err == nil {
			if err := os.Rename(path, path+".bak."+timestamp); err != nil {
				return fmt.Errorf("backup %s: %w", path, err)
			}
		}
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write server cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write server key: %w", err)
	}
	return nil
}

// ── helpers ────────────────────────────────────────────────

func createCACert(key *rsa.PrivateKey, cfg *Config) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber(),
		Subject: pkix.Name{
			Organization: []string{cfg.Org},
			CommonName:   "providapt-ca",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(cfg.ValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func serialNumber() *big.Int {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serial
}

func writePrivateKey(path string, key *rsa.PrivateKey) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func writeCert(path string, cert *x509.Certificate) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// CertFingerprint returns the SHA-256 fingerprint of a PEM certificate file.
func CertFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM block in %s", certPath)
	}
	fp := sha256.Sum256(block.Bytes)
	hexParts := make([]string, len(fp))
	for i, b := range fp {
		hexParts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(hexParts, ":"), nil
}
