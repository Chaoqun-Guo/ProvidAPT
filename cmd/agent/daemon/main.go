// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/analyzer"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/loader"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/pipeline"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	mgmt "github.com/Chaoqun-Guo/ProvidAPT/internal/policy/mgmt"
	storage "github.com/Chaoqun-Guo/ProvidAPT/internal/storage/format"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/alertflow"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/api"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/logx"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/metrics"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/notify"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/sanity"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/secure"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/supportbundle"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/telemetry"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/ticketing"
	"gopkg.in/yaml.v3"
)

const pidFile = "/var/run/providaptd.pid"
const ringBufSize = 1024
const deliveryAuditHistoryLimit = 32
const controlActionHistoryLimit = 24

type deliveryActionAuditStore struct {
	mu      sync.RWMutex
	entries []api.NotifyDeliveryAudit
	limit   int
}

type controlActionAuditStore struct {
	mu      sync.RWMutex
	entries []api.ControlActionAudit
	limit   int
}

type supportBundleState struct {
	mu      sync.RWMutex
	summary api.SupportBundleSummary
}

type licenseState struct {
	mu      sync.RWMutex
	summary api.LicenseStatus
}

type upgradeState struct {
	mu      sync.RWMutex
	summary api.UpgradeReadiness
}

type licenseDocument struct {
	ID        string `json:"id" yaml:"id"`
	Customer  string `json:"customer" yaml:"customer"`
	Edition   string `json:"edition" yaml:"edition"`
	IssuedAt  string `json:"issued_at" yaml:"issued_at"`
	ExpiresAt string `json:"expires_at" yaml:"expires_at"`
	Signature string `json:"signature" yaml:"signature"`
}

type revocationPayload struct {
	RevokedIDs []string `json:"revoked_ids" yaml:"revoked_ids"`
}

func newControlActionAuditStore(limit int) *controlActionAuditStore {
	if limit <= 0 {
		limit = controlActionHistoryLimit
	}
	return &controlActionAuditStore{
		entries: make([]api.ControlActionAudit, 0, limit),
		limit:   limit,
	}
}

func (s *controlActionAuditStore) record(action, actor, role, targetID, note, status, message string) {
	if s == nil {
		return
	}
	entry := api.ControlActionAudit{
		Action:      strings.TrimSpace(action),
		Actor:       strings.TrimSpace(actor),
		Role:        strings.TrimSpace(role),
		TargetID:    strings.TrimSpace(targetID),
		Status:      strings.TrimSpace(status),
		Message:     strings.TrimSpace(message),
		Note:        strings.TrimSpace(note),
		PerformedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if entry.Status == "" {
		entry.Status = "unknown"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append([]api.ControlActionAudit{entry}, s.entries...)
	if len(s.entries) > s.limit {
		s.entries = s.entries[:s.limit]
	}
}

func (s *controlActionAuditStore) snapshot() []api.ControlActionAudit {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]api.ControlActionAudit, len(s.entries))
	copy(out, s.entries)
	return out
}

func (s *supportBundleState) snapshot() api.SupportBundleSummary {
	if s == nil {
		return api.SupportBundleSummary{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.summary
	if out.History != nil {
		history := make([]api.ControlActionAudit, len(out.History))
		copy(history, out.History)
		out.History = history
	}
	return out
}

func (s *supportBundleState) update(bundlePath, reason, actor, role, status, performedAt string, history []api.ControlActionAudit) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.summary.LastBundlePath = strings.TrimSpace(bundlePath)
	s.summary.LastReason = strings.TrimSpace(reason)
	s.summary.LastActor = strings.TrimSpace(actor)
	s.summary.LastRole = strings.TrimSpace(role)
	s.summary.LastStatus = strings.TrimSpace(status)
	s.summary.LastBundleAt = strings.TrimSpace(performedAt)
	if history != nil {
		s.summary.History = make([]api.ControlActionAudit, len(history))
		copy(s.summary.History, history)
	}
}

func (s *supportBundleState) updateArchive(archivePath, archivedAt string, redacted bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.summary.LastArchivePath = strings.TrimSpace(archivePath)
	s.summary.LastArchiveAt = strings.TrimSpace(archivedAt)
	s.summary.Redacted = redacted
	s.summary.DownloadURL = ""
	if s.summary.LastArchivePath != "" {
		s.summary.DownloadURL = "/api/v1/control/support/download"
	}
}

func (s *licenseState) snapshot() api.LicenseStatus {
	if s == nil {
		return api.LicenseStatus{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.summary
	if out.History != nil {
		history := make([]api.ControlActionAudit, len(out.History))
		copy(history, out.History)
		out.History = history
	}
	return out
}

func (s *licenseState) update(summary api.LicenseStatus) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.summary = summary
}

func (s *upgradeState) snapshot() api.UpgradeReadiness {
	if s == nil {
		return api.UpgradeReadiness{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.summary
	if out.History != nil {
		history := make([]api.ControlActionAudit, len(out.History))
		copy(history, out.History)
		out.History = history
	}
	return out
}

func (s *upgradeState) update(summary api.UpgradeReadiness) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.summary = summary
}

func parseLicenseDocument(data []byte) (licenseDocument, error) {
	var doc licenseDocument
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return doc, fmt.Errorf("license file is empty")
	}
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, &doc); err != nil {
			return doc, err
		}
		return doc, nil
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return doc, err
	}
	return doc, nil
}

func licenseSignaturePayload(doc licenseDocument) string {
	return strings.Join([]string{
		"id=" + strings.TrimSpace(doc.ID),
		"customer=" + strings.TrimSpace(doc.Customer),
		"edition=" + strings.TrimSpace(doc.Edition),
		"issued_at=" + strings.TrimSpace(doc.IssuedAt),
		"expires_at=" + strings.TrimSpace(doc.ExpiresAt),
	}, "\n")
}

func verifyLicenseSignature(doc licenseDocument, signingKey string) bool {
	if strings.TrimSpace(doc.Signature) == "" || strings.TrimSpace(signingKey) == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write([]byte(licenseSignaturePayload(doc)))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(doc.Signature))), []byte(expected))
}

func loadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		pubAny, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
		if parseErr != nil {
			return nil, parseErr
		}
		pub, ok := pubAny.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not ed25519")
		}
		return pub, nil
	}
	raw := strings.TrimSpace(string(data))
	if decoded, decodeErr := hex.DecodeString(raw); decodeErr == nil && len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(raw)
	if decodeErr != nil {
		return nil, fmt.Errorf("unsupported public key encoding")
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected public key size")
	}
	return ed25519.PublicKey(decoded), nil
}

func loadDetachedSignature(path string) ([]byte, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(data))
	if decoded, decodeErr := hex.DecodeString(raw); decodeErr == nil {
		return decoded, nil
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(raw)
	if decodeErr == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("unsupported signature encoding")
}

func verifyEd25519Signature(signaturePath, publicKeyPath, message string) (present bool, verified bool, err error) {
	signaturePath = strings.TrimSpace(signaturePath)
	publicKeyPath = strings.TrimSpace(publicKeyPath)
	if signaturePath == "" {
		return false, false, nil
	}
	signature, err := loadDetachedSignature(signaturePath)
	if err != nil {
		return false, false, err
	}
	present = true
	if publicKeyPath == "" {
		return true, false, fmt.Errorf("public key path not configured")
	}
	pub, err := loadEd25519PublicKey(publicKeyPath)
	if err != nil {
		return true, false, err
	}
	return true, ed25519.Verify(pub, []byte(message), signature), nil
}

func verifyEd25519InlineSignature(signatureValue, publicKeyPath, message string) (present bool, verified bool, err error) {
	signatureValue = strings.TrimSpace(signatureValue)
	if signatureValue == "" {
		return false, false, nil
	}
	var signature []byte
	if decoded, decodeErr := hex.DecodeString(signatureValue); decodeErr == nil {
		signature = decoded
	} else if decoded, decodeErr := base64.StdEncoding.DecodeString(signatureValue); decodeErr == nil {
		signature = decoded
	} else {
		return true, false, fmt.Errorf("unsupported signature encoding")
	}
	pub, err := loadEd25519PublicKey(publicKeyPath)
	if err != nil {
		return true, false, err
	}
	return true, ed25519.Verify(pub, []byte(message), signature), nil
}

func parseFlexibleTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	layouts := []string{time.RFC3339, "2006-01-02"}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported time format: %s", value)
}

func loadRevokedIDs(cfg *config.Config) ([]string, string, bool, error) {
	base := make([]string, 0, len(cfg.License.RevokedIDs))
	base = append(base, cfg.License.RevokedIDs...)
	revocationURL := strings.TrimSpace(cfg.License.RevocationURL)
	cachePath := strings.TrimSpace(cfg.License.RevocationCache)
	sigURL := strings.TrimSpace(cfg.License.RevocationSigURL)
	sigCache := strings.TrimSpace(cfg.License.RevocationSigCache)
	if revocationURL == "" {
		if len(base) == 0 {
			return base, "", false, nil
		}
		return dedupeStrings(base), "config:license.revoked_ids", false, nil
	}

	parsePayload := func(data []byte) ([]string, error) {
		var payload revocationPayload
		if err := json.Unmarshal(data, &payload); err == nil && len(payload.RevokedIDs) > 0 {
			return payload.RevokedIDs, nil
		}
		if err := yaml.Unmarshal(data, &payload); err == nil && len(payload.RevokedIDs) > 0 {
			return payload.RevokedIDs, nil
		}
		var direct []string
		if err := json.Unmarshal(data, &direct); err == nil {
			return direct, nil
		}
		if err := yaml.Unmarshal(data, &direct); err == nil {
			return direct, nil
		}
		return nil, fmt.Errorf("unsupported revocation payload")
	}

	fetchRemote := func(url string) ([]byte, error) {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("revocation fetch status %d", resp.StatusCode)
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return body, nil
	}

	writeCache := func(path string, body []byte) {
		if strings.TrimSpace(path) == "" {
			return
		}
		_ = os.MkdirAll(filepath.Dir(path), 0755)
		_ = os.WriteFile(path, body, 0644)
	}

	if strings.HasPrefix(strings.ToLower(revocationURL), "http://") || strings.HasPrefix(strings.ToLower(revocationURL), "https://") {
		if body, err := fetchRemote(revocationURL); err == nil {
			if sigURL == "" && strings.TrimSpace(cfg.License.PublicKeyPath) != "" {
				sigURL = revocationURL + ".sig"
			}
			if sigCache == "" && cachePath != "" {
				sigCache = cachePath + ".sig"
			}
			if strings.TrimSpace(cfg.License.PublicKeyPath) != "" && sigURL != "" {
				sigBody, sigErr := fetchRemote(sigURL)
				if sigErr != nil {
					return dedupeStrings(base), "config:license.revoked_ids", false, sigErr
				}
				writeCache(sigCache, sigBody)
				if err := os.WriteFile(filepath.Join(os.TempDir(), "providapt-revocation.sig"), sigBody, 0644); err == nil {
					tmpSig := filepath.Join(os.TempDir(), "providapt-revocation.sig")
					defer os.Remove(tmpSig)
					present, verified, verifyErr := verifyEd25519Signature(tmpSig, cfg.License.PublicKeyPath, string(body))
					if verifyErr != nil || !present || !verified {
						if verifyErr == nil {
							verifyErr = fmt.Errorf("revocation signature mismatch")
						}
						return dedupeStrings(base), "config:license.revoked_ids", false, verifyErr
					}
				}
			}
			writeCache(cachePath, body)
			if ids, parseErr := parsePayload(body); parseErr == nil {
				return dedupeStrings(append(base, ids...)), "remote:" + revocationURL, strings.TrimSpace(cfg.License.PublicKeyPath) != "", nil
			} else {
				return dedupeStrings(base), "config:license.revoked_ids", false, parseErr
			}
		} else if cachePath != "" {
			if cached, readErr := os.ReadFile(cachePath); readErr == nil {
				if strings.TrimSpace(cfg.License.PublicKeyPath) != "" && sigCache != "" {
					present, verified, verifyErr := verifyEd25519Signature(sigCache, cfg.License.PublicKeyPath, string(cached))
					if verifyErr != nil || !present || !verified {
						return dedupeStrings(base), "config:license.revoked_ids", false, err
					}
				}
				if ids, parseErr := parsePayload(cached); parseErr == nil {
					return dedupeStrings(append(base, ids...)), "cache:" + cachePath, strings.TrimSpace(cfg.License.PublicKeyPath) != "", nil
				}
			}
			return dedupeStrings(base), "config:license.revoked_ids", false, err
		} else {
			return dedupeStrings(base), "config:license.revoked_ids", false, err
		}
	}

	if fileData, err := os.ReadFile(revocationURL); err == nil {
		if ids, parseErr := parsePayload(fileData); parseErr == nil {
			return dedupeStrings(append(base, ids...)), "file:" + revocationURL, false, nil
		}
	}
	return dedupeStrings(base), "config:license.revoked_ids", false, nil
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func inspectUpgradePackage(packagePath, expectedSHA256, signaturePath, signingKey, publicKeyPath, rollbackPlan string) api.UpgradeReadiness {
	summary := api.UpgradeReadiness{
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
		CurrentVersion: version.String(),
		GuidePath:      "docs/developer/testing.md",
		PackagePath:    strings.TrimSpace(packagePath),
		ExpectedSHA256: strings.TrimSpace(expectedSHA256),
		SignaturePath:  strings.TrimSpace(signaturePath),
		RollbackPlan:   strings.TrimSpace(rollbackPlan),
	}
	summary.RollbackReady = summary.RollbackPlan != ""
	if summary.PackagePath == "" {
		summary.LastError = "upgrade package path not configured"
		return summary
	}
	data, err := os.ReadFile(summary.PackagePath)
	if err != nil {
		summary.LastError = err.Error()
		return summary
	}
	summary.PackagePresent = true
	hash := sha256.Sum256(data)
	summary.PackageSHA256 = hex.EncodeToString(hash[:])
	if summary.ExpectedSHA256 == "" {
		summary.LastError = "expected upgrade checksum not configured"
		return summary
	}
	if strings.EqualFold(summary.ExpectedSHA256, summary.PackageSHA256) {
		summary.PackageVerified = true
		if strings.TrimSpace(publicKeyPath) != "" {
			present, verified, sigErr := verifyEd25519Signature(summary.SignaturePath, publicKeyPath, summary.PackageSHA256)
			summary.SignaturePresent = present
			summary.SignatureVerified = verified
			if sigErr != nil {
				summary.LastError = sigErr.Error()
			}
		} else {
			present, verified, sigErr := verifyUpgradeSignature(summary.SignaturePath, signingKey, summary.PackageSHA256)
			summary.SignaturePresent = present
			summary.SignatureVerified = verified
			if sigErr != nil {
				summary.LastError = sigErr.Error()
			}
		}
		if summary.SignaturePresent && !summary.SignatureVerified && summary.LastError == "" {
			summary.LastError = "upgrade signature mismatch"
		}
		summary.PreflightReady = summary.PackageVerified && (!summary.SignaturePresent || summary.SignatureVerified) && summary.RollbackReady && summary.LastError == ""
		return summary
	}
	summary.LastError = "upgrade package checksum mismatch"
	return summary
}

func verifyUpgradeSignature(signaturePath, signingKey, packageSHA256 string) (present bool, verified bool, err error) {
	signaturePath = strings.TrimSpace(signaturePath)
	signingKey = strings.TrimSpace(signingKey)
	if signaturePath == "" {
		return false, false, nil
	}
	data, readErr := os.ReadFile(signaturePath)
	if readErr != nil {
		return false, false, readErr
	}
	present = true
	if signingKey == "" {
		return true, false, fmt.Errorf("upgrade signing key not configured")
	}
	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write([]byte(strings.TrimSpace(packageSHA256)))
	expected := hex.EncodeToString(mac.Sum(nil))
	actual := strings.ToLower(strings.TrimSpace(string(data)))
	return true, hmac.Equal([]byte(actual), []byte(expected)), nil
}

func downloadToPath(sourceURL, destPath string) error {
	sourceURL = strings.TrimSpace(sourceURL)
	destPath = strings.TrimSpace(destPath)
	if sourceURL == "" || destPath == "" {
		return fmt.Errorf("download source and destination are required")
	}
	if strings.HasPrefix(strings.ToLower(sourceURL), "http://") || strings.HasPrefix(strings.ToLower(sourceURL), "https://") {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(sourceURL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("download status %d", resp.StatusCode)
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		_ = os.MkdirAll(filepath.Dir(destPath), 0755)
		return os.WriteFile(destPath, body, 0644)
	}
	data, err := os.ReadFile(sourceURL)
	if err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(destPath), 0755)
	return os.WriteFile(destPath, data, 0644)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func newDeliveryActionAuditStore(limit int) *deliveryActionAuditStore {
	if limit <= 0 {
		limit = deliveryAuditHistoryLimit
	}
	return &deliveryActionAuditStore{
		entries: make([]api.NotifyDeliveryAudit, 0, limit),
		limit:   limit,
	}
}

func (s *deliveryActionAuditStore) record(req api.NotifyDeliveryActionRequest, result api.NotifyDeliveryActionResult, err error) {
	if s == nil {
		return
	}
	entry := api.NotifyDeliveryAudit{
		Action:      strings.TrimSpace(req.Action),
		Actor:       strings.TrimSpace(req.Actor),
		Role:        strings.TrimSpace(req.Role),
		Note:        strings.TrimSpace(req.Note),
		DeliveryID:  strings.TrimSpace(req.DeliveryID),
		Status:      result.Status,
		Message:     result.Message,
		TicketKey:   result.TicketKey,
		TicketURL:   result.TicketURL,
		TicketType:  result.TicketType,
		Processed:   result.Processed,
		Succeeded:   result.Succeeded,
		Failed:      result.Failed,
		Skipped:     result.Skipped,
		PerformedAt: result.PerformedAt,
	}
	if entry.PerformedAt == "" {
		entry.PerformedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if entry.Status == "" {
		entry.Status = "unknown"
	}
	if err != nil && entry.Message == "" {
		entry.Message = err.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append([]api.NotifyDeliveryAudit{entry}, s.entries...)
	if len(s.entries) > s.limit {
		s.entries = s.entries[:s.limit]
	}
}

func (s *deliveryActionAuditStore) snapshot() []api.NotifyDeliveryAudit {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]api.NotifyDeliveryAudit, len(s.entries))
	copy(out, s.entries)
	return out
}

func main() {
	// ── Panic recovery & crash snapshot ──────────────────
	defer supportbundle.HandleCrash()

	// ── CLI flags ────────────────────────────────────────────
	configPath := flag.String("config", "providapt.toml", "Path to configuration file")
	logLevel := flag.String("log-level", "", "Override log level (debug|info|warn|error)")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	// ── Load config ─────────────────────────────────────────
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		os.Exit(1)
	}

	// ── Structured logging ───────────────────────────────────
	logLevelVal := cfg.Log.Level
	if *logLevel != "" {
		logLevelVal = *logLevel // CLI flag overrides config
	}
	logx.Init(logLevelVal, cfg.Log.Format)
	logx.System().Info("starting", "version", version.String(), "config", *configPath)

	// ── Audit log store ──────────────────────────────────
	auditStore, err := audit.New(cfg.Output.Dir)
	if err != nil {
		logx.System().Warn("audit store init", "error", err)
	}
	if auditStore != nil {
		defer auditStore.Close()
		auditStore.Log(audit.Entry{
			Category: audit.CatSystem,
			Severity: "INFO",
			Message:  "Daemon starting",
			Source:   "daemon",
			Details: map[string]interface{}{
				"version": version.String(),
				"config":  *configPath,
			},
		})
		defer func() {
			auditStore.Log(audit.Entry{
				Category: audit.CatSystem,
				Severity: "INFO",
				Message:  "Daemon shutting down",
				Source:   "daemon",
			})
		}()
	}

	// ── PID file ──────────────────────────────────────────
	writePIDFile()
	defer os.Remove(pidFile)

	// ── Self-check ───────────────────────────────────────
	var sanitySkipList []string
	if raw := strings.TrimSpace(os.Getenv("PROVIDAPT_SKIP_SANITY_CHECKS")); raw != "" {
		for _, item := range strings.Split(raw, ",") {
			name := strings.TrimSpace(item)
			if name != "" {
				sanitySkipList = append(sanitySkipList, name)
			}
		}
		if len(sanitySkipList) > 0 {
			logx.System().Warn("skipping sanity checks via environment", "checks", sanitySkipList)
		}
	}
	sanityReport := sanity.RunChecks(cfg, sanitySkipList)
	for _, r := range sanityReport.Results {
		msg := r.Message
		if r.FixSuggestion != "" {
			msg += " | fix: " + r.FixSuggestion
		}
		if r.Status == sanity.FAIL {
			logx.System().Error("sanity check failed", "check", r.Name, "detail", msg)
		} else if r.Status == sanity.WARN {
			logx.System().Warn("sanity check warning", "check", r.Name, "detail", msg)
		} else {
			logx.System().Info("sanity check passed", "check", r.Name)
		}
	}
	if sanityReport.HasFailures() {
		logx.System().Error("environment check failed — aborting startup",
			"summary", sanityReport.Summary())
		os.Exit(1)
	}
	logx.System().Info("all sanity checks passed", "summary", sanityReport.Summary())

	// ── eBPF loader ─────────────────────────────────────
	bpfLoader, err := loader.NewWithAudit(cfg, auditStore)
	if err != nil {
		logx.System().Error("loader init failed", "error", err)
		os.Exit(1)
	}
	defer bpfLoader.Close()

	// ── Encryption at rest ──────────────────────────────
	var encryptKey []byte
	if cfg.Storage.Encrypt {
		ek, err := secure.LoadOrGenerateKey(cfg.Storage.KeyFile)
		if err != nil {
			logx.System().Error("encryption key init failed", "error", err)
			os.Exit(1)
		}
		encryptKey = ek.Bytes()
		logx.System().Info("storage encryption enabled", "key_file", cfg.Storage.KeyFile)
	}

	// ── Least privilege: pin eBPF maps & drop root ──────
	if secure.IsPrivileged() {
		bpfLoader.PinMaps("/sys/fs/bpf/providapt")

		// Apply default excludes before dropping privileges
		if err := bpfLoader.Ctrl.DefaultExcludes(); err != nil {
			logx.System().Warn("default excludes failed", "error", err)
		}

		if err := secure.EnsureDataDirOwnership(cfg.Output.Dir); err != nil {
			logx.System().Warn("data dir ownership", "error", err)
		}
		if strings.EqualFold(strings.TrimSpace(os.Getenv("PROVIDAPT_SKIP_PRIVILEGE_DROP")), "1") {
			logx.System().Warn("skipping privilege drop via environment")
		} else {
			if err := secure.DropPrivileges(); err != nil {
				logx.System().Error("privilege drop failed", "error", err)
				os.Exit(1)
			}
			logx.System().Info("privileges dropped to providapt user")
		}
	}

	// ── Ring buffer reader ──────────────────────────────
	eventCh, errCh := collector.Start(bpfLoader.RB)

	// ── Provenance graph (in-memory DAG) ────────────────
	graph := provenance.NewGraph()

	// ── Ingestion pipeline (cache + RocksDB + merge) ────
	pipeCfg := pipeline.DefaultConfig()
	pipeCfg.StorePath = filepath.Join(cfg.Output.Dir, "store")
	pipeCfg.MaxCacheSize = 8192
	pipeCfg.MergeWindow = 5 * time.Second
	pipeCfg.EncryptionKey = encryptKey

	pipe, err := pipeline.New(graph, pipeCfg)
	if err != nil {
		logx.System().Error("pipeline init failed", "error", err)
		os.Exit(1)
	}
	defer pipe.Stop()
	pipe.Start()

	// ── APT analyzer ────────────────────────────────────
	aptCfg := analyzer.DefaultConfig()
	aptCfg.ScanInterval = 30 * time.Second
	apt := analyzer.New(graph, aptCfg)
	apt.Start()
	defer apt.Stop()

	// ── Connect sketch integrator (graph anomaly detection) ──
	si := analyzer.NewSketchIntegrator(analyzer.DefaultSketchConfig())
	apt.SetSketchIntegrator(si)
	defer si.Stop()
	// ── Notification manager ────────────────────────────
	notifyMgr := initNotifier(cfg)
	if notifyMgr != nil {
		defer notifyMgr.Close()
	}
	ticketClient := initTicketClient(cfg)
	alertWorkflow := alertflow.NewManager()
	if cfg.Notify.MinInterval != "" {
		if dedupWindow, err := time.ParseDuration(cfg.Notify.MinInterval); err == nil && dedupWindow > 0 {
			alertWorkflow.SetDedupWindow(dedupWindow)
		}
	}

	// ── Raw event log writer ────────────────────────────
	writer, err := storage.NewWriter(cfg.Output.Dir, cfg.Output.Format)
	if err != nil {
		logx.System().Error("storage writer init failed", "error", err)
		os.Exit(1)
	}
	defer writer.Close()

	// ── API server with /health and /metrics ────────────
	apiServer := api.NewServer(cfg.API.REST, graph, nil)
	deliveryAudit := newDeliveryActionAuditStore(deliveryAuditHistoryLimit)
	policyAudit := newControlActionAuditStore(controlActionHistoryLimit)
	workflowAudit := newControlActionAuditStore(controlActionHistoryLimit)
	fleetAudit := newControlActionAuditStore(controlActionHistoryLimit)
	supportAudit := newControlActionAuditStore(controlActionHistoryLimit)
	licenseAudit := newControlActionAuditStore(controlActionHistoryLimit)
	upgradeAudit := newControlActionAuditStore(controlActionHistoryLimit)
	supportState := &supportBundleState{}
	licenseSummaryState := &licenseState{}
	upgradeSummaryState := &upgradeState{}
	apiServer.SetAPIAuth(cfg.API.AuthKeys, cfg.API.AuthRoles, cfg.API.AuthIdentities, cfg.API.AuthEnabled)
	apiServer.SetCORSOrigins(cfg.API.CORSOrigins)
	if cfg.API.RateLimitPerSec > 0 {
		apiServer.SetRateLimit(cfg.API.RateLimitPerSec, cfg.API.RateLimitBurst)
	}
	metrics.MustRegister()

	// Health check closure — populated every iteration
	var (
		eventsIngested  uint64
		eventsDropped   uint64
		pipelineHealthy = true
		storeHealthy    = true
		sanityPassed    = !sanityReport.HasFailures()
		startTime       = time.Now()
	)

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}

	telemetryInterval, err := time.ParseDuration(cfg.Telemetry.Interval)
	if err != nil || telemetryInterval <= 0 {
		telemetryInterval = 30 * time.Second
	}

	buildTelemetrySummary := func() telemetry.Summary {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		status := "DEGRADED"
		if pipelineHealthy && storeHealthy {
			status = "HEALTHY"
		}

		return telemetry.Summary{
			AgentID:          hostname,
			Version:          version.String(),
			Status:           status,
			UptimeSeconds:    int64(time.Since(startTime).Seconds()),
			EventsIngested:   eventsIngested,
			EventsDropped:    eventsDropped,
			MemoryBytes:      m.Alloc,
			PipelineHealthy:  pipelineHealthy,
			StoreHealthy:     storeHealthy,
			AttachmentMode:   bpfLoader.ModeName(),
			TimestampUnixSec: time.Now().Unix(),
		}
	}

	var mgmtServer *mgmt.Server

	telemetryReporter := telemetry.NewReporter(telemetry.ReporterConfig{
		Endpoint:   cfg.Telemetry.Endpoint,
		Interval:   telemetryInterval,
		EnableTLS:  cfg.Telemetry.EnableTLS,
		CertFile:   cfg.Telemetry.CertFile,
		KeyFile:    cfg.Telemetry.KeyFile,
		CAFile:     cfg.Telemetry.CAFile,
		ServerName: cfg.Telemetry.ServerName,
	}, buildTelemetrySummary)
	if err := telemetryReporter.Start(context.Background()); err != nil {
		logx.System().Warn("telemetry reporter start failed", "error", err)
	}
	defer telemetryReporter.Stop()

	apiServer.SetHealthFunc(func() api.HealthStatus {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		reporterStatus := telemetryReporter.Status()
		hs := api.HealthStatus{
			Status:             healthStatus(pipelineHealthy, storeHealthy),
			UptimeSeconds:      int64(time.Since(startTime).Seconds()),
			EbpfCollector:      bpfLoader.RB != nil,
			PipelineHealthy:    pipelineHealthy,
			StoreHealthy:       storeHealthy,
			EventsIngested:     eventsIngested,
			EventsDropped:      eventsDropped,
			MemoryBytes:        m.Alloc,
			Version:            version.String(),
			TelemetryEnabled:   reporterStatus.Enabled,
			TelemetryHealthy:   !reporterStatus.Enabled || reporterStatus.ConsecutiveFailures == 0,
			TelemetryLastError: reporterStatus.LastError,
		}
		if !reporterStatus.LastSuccess.IsZero() {
			hs.TelemetryLastSuccess = reporterStatus.LastSuccess.UTC().Format(time.RFC3339)
		}
		if sanityPassed {
			hs.SanityCheck = "pass"
		} else {
			hs.SanityCheck = "fail"
		}
		return hs
	})
	apiServer.SetClusterOverviewFunc(func() api.ClusterOverview {
		local := buildTelemetrySummary()
		agentsByID := map[string]api.ClusterAgent{
			local.AgentID: {
				AgentID:         local.AgentID,
				Status:          local.Status,
				Version:         local.Version,
				LastReportAt:    time.Now().UTC().Format(time.RFC3339),
				EventsIngested:  local.EventsIngested,
				EventsDropped:   local.EventsDropped,
				MemoryBytes:     local.MemoryBytes,
				UptimeSeconds:   local.UptimeSeconds,
				PipelineHealthy: local.PipelineHealthy,
				StoreHealthy:    local.StoreHealthy,
				AttachmentMode:  local.AttachmentMode,
			},
		}
		if mgmtServer != nil {
			for _, agent := range mgmtServer.TelemetryOverview() {
				agentsByID[agent.AgentID] = api.ClusterAgent{
					AgentID:         agent.AgentID,
					Group:           agent.Group,
					Tags:            agent.Tags,
					Status:          agent.Status,
					Version:         agent.Version,
					LastReportAt:    agent.LastReportAt.UTC().Format(time.RFC3339),
					EventsIngested:  agent.EventsIngested,
					EventsDropped:   agent.EventsDropped,
					MemoryBytes:     agent.MemoryBytes,
					UptimeSeconds:   agent.UptimeSeconds,
					PipelineHealthy: agent.PipelineHealthy,
					StoreHealthy:    agent.StoreHealthy,
					AttachmentMode:  agent.AttachmentMode,
				}
			}
		}

		overview := api.ClusterOverview{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Agents:    make([]api.ClusterAgent, 0, len(agentsByID)),
		}
		for _, agent := range agentsByID {
			overview.Agents = append(overview.Agents, agent)
			if agent.Status == "HEALTHY" || agent.Status == "healthy" {
				overview.HealthyAgents++
			} else {
				overview.DegradedAgents++
			}
		}
		overview.TotalAgents = len(overview.Agents)
		return overview
	})
	apiServer.SetFleetListFunc(func(group, tag string) api.FleetList {
		fleet := api.FleetList{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Group:     group,
			Tag:       tag,
			Agents:    []api.ClusterAgent{},
			History:   fleetAudit.snapshot(),
		}
		local := buildTelemetrySummary()
		localAgent := api.ClusterAgent{
			AgentID:         local.AgentID,
			Status:          local.Status,
			Version:         local.Version,
			LastReportAt:    time.Now().UTC().Format(time.RFC3339),
			EventsIngested:  local.EventsIngested,
			EventsDropped:   local.EventsDropped,
			MemoryBytes:     local.MemoryBytes,
			UptimeSeconds:   local.UptimeSeconds,
			PipelineHealthy: local.PipelineHealthy,
			StoreHealthy:    local.StoreHealthy,
			AttachmentMode:  local.AttachmentMode,
		}
		includeLocal := group == "" && tag == ""
		if includeLocal {
			fleet.Agents = append(fleet.Agents, localAgent)
		}
		if mgmtServer != nil {
			for _, agent := range mgmtServer.FleetSnapshot(mgmt.FleetFilter{Group: group, Tag: tag}) {
				fleet.Agents = append(fleet.Agents, api.ClusterAgent{
					AgentID:         agent.AgentID,
					Group:           agent.Group,
					Tags:            agent.Tags,
					Status:          agent.Status,
					Version:         agent.Version,
					LastReportAt:    agent.LastReportAt.UTC().Format(time.RFC3339),
					EventsIngested:  agent.EventsIngested,
					EventsDropped:   agent.EventsDropped,
					MemoryBytes:     agent.MemoryBytes,
					UptimeSeconds:   agent.UptimeSeconds,
					PipelineHealthy: agent.PipelineHealthy,
					StoreHealthy:    agent.StoreHealthy,
					AttachmentMode:  agent.AttachmentMode,
				})
			}
		}
		return fleet
	})
	apiServer.SetFleetUpdateFunc(func(update api.FleetUpdate) error {
		if mgmtServer == nil {
			err := fmt.Errorf("mgmt server not available")
			fleetAudit.record("fleet_update", update.Actor, update.Role, update.AgentID, update.Note, "failed", err.Error())
			return err
		}
		mgmtServer.UpsertAgentMetadata(update.AgentID, update.Group, update.Tags)
		fleetAudit.record(
			"fleet_update",
			update.Actor,
			update.Role,
			update.AgentID,
			update.Note,
			"updated",
			fmt.Sprintf("fleet metadata updated: group=%s tags=%s", strings.TrimSpace(update.Group), strings.Join(update.Tags, ",")),
		)
		return nil
	})
	apiServer.SetSupportBundleFunc(func() api.SupportBundleSummary {
		summary := supportState.snapshot()
		summary.History = supportAudit.snapshot()
		return summary
	})
	apiServer.SetSupportBundleDownloadFunc(func(actor, role string) (api.SupportBundleDownload, error) {
		summary := supportState.snapshot()
		if strings.TrimSpace(summary.LastArchivePath) == "" {
			return api.SupportBundleDownload{}, fmt.Errorf("support bundle archive not available")
		}
		supportAudit.record("support_bundle_download", actor, role, summary.LastArchivePath, "", "downloaded", "support bundle archive downloaded")
		if auditStore != nil {
			_ = auditStore.Log(audit.Entry{
				Category: audit.CatAdmin,
				Severity: "INFO",
				Message:  "Support bundle archive downloaded",
				Source:   "supportbundle",
				Details: map[string]interface{}{
					"archive_path": summary.LastArchivePath,
					"actor":        actor,
					"role":         role,
				},
			})
		}
		return api.SupportBundleDownload{
			Path:     summary.LastArchivePath,
			FileName: filepath.Base(summary.LastArchivePath),
		}, nil
	})
	apiServer.SetSupportBundleActionFunc(func(req api.SupportBundleActionRequest) (api.SupportBundleActionResult, error) {
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "manual support bundle export"
		}
		if note := strings.TrimSpace(req.Note); note != "" {
			reason = reason + " | note: " + note
		}
		bundleRoot := filepath.Join(cfg.Output.Dir, "support-bundle")
		bundlePath, err := supportbundle.CaptureTo(bundleRoot, reason)
		performedAt := time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			supportAudit.record("support_bundle_export", req.Actor, req.Role, "", req.Note, "failed", err.Error())
			supportState.update("", reason, req.Actor, req.Role, "failed", performedAt, supportAudit.snapshot())
			if auditStore != nil {
				_ = auditStore.Log(audit.Entry{
					Category: audit.CatAdmin,
					Severity: "WARNING",
					Message:  "Support bundle export failed",
					Source:   "supportbundle",
					Details: map[string]interface{}{
						"actor":  req.Actor,
						"role":   req.Role,
						"note":   req.Note,
						"reason": reason,
						"error":  err.Error(),
					},
				})
			}
			return api.SupportBundleActionResult{
				Status:      "failed",
				Message:     err.Error(),
				Reason:      reason,
				PerformedAt: performedAt,
			}, err
		}
		archivePath, archiveErr := supportbundle.CreateArchive(bundlePath, supportbundle.ArchiveOptions{RedactSensitive: cfg.SupportBundle.RedactArchives})
		status := "archived"
		message := "support bundle exported and archived"
		if archiveErr != nil {
			status = "created_partial"
			message = "support bundle exported, archive creation failed: " + archiveErr.Error()
		}
		supportAudit.record("support_bundle_export", req.Actor, req.Role, bundlePath, req.Note, status, message)
		supportState.update(bundlePath, reason, req.Actor, req.Role, status, performedAt, supportAudit.snapshot())
		if auditStore != nil {
			severity := "INFO"
			if archiveErr != nil {
				severity = "WARNING"
			}
			_ = auditStore.Log(audit.Entry{
				Category: audit.CatAdmin,
				Severity: severity,
				Message:  "Support bundle exported",
				Source:   "supportbundle",
				Details: map[string]interface{}{
					"bundle_path":   bundlePath,
					"archive_path":  archivePath,
					"actor":         req.Actor,
					"role":          req.Role,
					"note":          req.Note,
					"reason":        reason,
					"redacted":      cfg.SupportBundle.RedactArchives,
					"archive_state": status,
				},
			})
		}
		if archiveErr == nil {
			supportState.updateArchive(archivePath, performedAt, true)
			if cleanupErr := supportbundle.CleanupArchives(bundleRoot, cfg.SupportBundle.RetainArchives); cleanupErr != nil {
				supportAudit.record("support_bundle_cleanup", req.Actor, req.Role, bundleRoot, req.Note, "failed", cleanupErr.Error())
				if auditStore != nil {
					_ = auditStore.Log(audit.Entry{
						Category: audit.CatAdmin,
						Severity: "WARNING",
						Message:  "Support bundle cleanup failed",
						Source:   "supportbundle",
						Details: map[string]interface{}{
							"root":   bundleRoot,
							"actor":  req.Actor,
							"role":   req.Role,
							"error":  cleanupErr.Error(),
							"retain": cfg.SupportBundle.RetainArchives,
						},
					})
				}
			}
		} else {
			supportState.updateArchive("", "", false)
		}
		downloadURL := ""
		if archiveErr == nil {
			downloadURL = "/api/v1/control/support/download"
		}
		return api.SupportBundleActionResult{
			Status:      status,
			Message:     message,
			BundlePath:  bundlePath,
			ArchivePath: archivePath,
			DownloadURL: downloadURL,
			Redacted:    archiveErr == nil,
			Reason:      reason,
			PerformedAt: performedAt,
		}, nil
	})
	apiServer.SetAuditQueryFunc(func(category, source string, limit int) api.AuditFeed {
		feed := api.AuditFeed{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Category:  strings.TrimSpace(category),
			Source:    strings.TrimSpace(source),
			Entries:   []api.AuditEntry{},
		}
		if auditStore == nil {
			return feed
		}
		var cat audit.Category
		switch strings.ToLower(strings.TrimSpace(category)) {
		case string(audit.CatAdmin):
			cat = audit.CatAdmin
		case string(audit.CatSecurity):
			cat = audit.CatSecurity
		case string(audit.CatIntegrity):
			cat = audit.CatIntegrity
		case string(audit.CatSystem):
			cat = audit.CatSystem
		}
		entries, err := auditStore.Query(cat, time.Time{}, limit)
		if err != nil {
			return feed
		}
		for _, entry := range entries {
			if source != "" && !strings.EqualFold(strings.TrimSpace(entry.Source), strings.TrimSpace(source)) {
				continue
			}
			feed.Entries = append(feed.Entries, api.AuditEntry{
				ID:        entry.ID,
				Timestamp: entry.Timestamp.UTC().Format(time.RFC3339),
				Category:  string(entry.Category),
				Severity:  entry.Severity,
				Message:   entry.Message,
				Source:    entry.Source,
				Details:   entry.Details,
			})
		}
		return feed
	})
	inspectLicense := func() api.LicenseStatus {
		summary := api.LicenseStatus{
			UpdatedAt:         time.Now().UTC().Format(time.RFC3339),
			Path:              strings.TrimSpace(cfg.License.Path),
			CurrentVersion:    version.String(),
			History:           licenseAudit.snapshot(),
			GracePeriodDays:   cfg.License.GracePeriodDays,
			SignaturePresent:  false,
			SignatureVerified: false,
		}
		if cached := licenseSummaryState.snapshot(); cached.LastValidatedAt != "" {
			summary.LastValidatedAt = cached.LastValidatedAt
			summary.LastError = cached.LastError
		}
		if summary.Path == "" {
			summary.LastError = "license path not configured"
			return summary
		}
		info, err := os.Stat(summary.Path)
		if err != nil {
			summary.LastError = err.Error()
			return summary
		}
		summary.Present = true
		summary.SizeBytes = info.Size()
		summary.ModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
		data, err := os.ReadFile(summary.Path)
		if err != nil {
			summary.LastError = err.Error()
			return summary
		}
		doc, err := parseLicenseDocument(data)
		if err != nil {
			return summary
		}
		summary.LicenseID = strings.TrimSpace(doc.ID)
		summary.Customer = strings.TrimSpace(doc.Customer)
		summary.Edition = strings.TrimSpace(doc.Edition)
		summary.IssuedAt = strings.TrimSpace(doc.IssuedAt)
		summary.ExpiresAt = strings.TrimSpace(doc.ExpiresAt)
		summary.SignaturePresent = strings.TrimSpace(doc.Signature) != ""
		revokedIDs, revocationSource, revocationVerified, revokeErr := loadRevokedIDs(cfg)
		summary.RevocationCheckedAt = time.Now().UTC().Format(time.RFC3339)
		summary.RevocationVerified = revocationVerified
		if revokeErr != nil && summary.LastError == "" {
			summary.LastError = revokeErr.Error()
		}
		for _, revokedID := range revokedIDs {
			if strings.EqualFold(strings.TrimSpace(revokedID), summary.LicenseID) && summary.LicenseID != "" {
				summary.Revoked = true
				summary.RevocationSource = revocationSource
				summary.LastError = "license has been revoked"
				break
			}
		}
		if summary.ExpiresAt != "" {
			expiresAt, parseErr := parseFlexibleTime(summary.ExpiresAt)
			if parseErr != nil {
				summary.LastError = parseErr.Error()
			} else {
				days := int(time.Until(expiresAt).Hours() / 24)
				summary.DaysRemaining = days
				summary.Expired = expiresAt.Before(time.Now())
				if summary.Expired && summary.GracePeriodDays > 0 {
					graceDeadline := expiresAt.Add(time.Duration(summary.GracePeriodDays) * 24 * time.Hour)
					if graceDeadline.After(time.Now()) {
						summary.InGracePeriod = true
					}
				}
			}
		}
		if summary.SignaturePresent {
			publicKeyPath := strings.TrimSpace(cfg.License.PublicKeyPath)
			if publicKeyPath != "" {
				present, verified, verifyErr := verifyEd25519InlineSignature(doc.Signature, publicKeyPath, licenseSignaturePayload(doc))
				summary.SignaturePresent = present
				summary.SignatureVerified = verified
				if verifyErr != nil {
					summary.LastError = verifyErr.Error()
				} else if !verified {
					summary.LastError = "license signature mismatch"
				}
			} else if strings.TrimSpace(cfg.License.SigningKey) == "" {
				summary.LastError = "license signing key not configured"
			} else {
				summary.SignatureVerified = verifyLicenseSignature(doc, cfg.License.SigningKey)
				if !summary.SignatureVerified {
					summary.LastError = "license signature mismatch"
				}
			}
		}
		return summary
	}
	apiServer.SetLicenseStatusFunc(func() api.LicenseStatus {
		summary := inspectLicense()
		licenseSummaryState.update(summary)
		return summary
	})
	apiServer.SetLicenseActionFunc(func(req api.LicenseActionRequest) (api.LicenseActionResult, error) {
		action := strings.ToLower(strings.TrimSpace(req.Action))
		if action == "" {
			action = "validate"
		}
		if action != "validate" && action != "refresh" {
			err := fmt.Errorf("unsupported license action: %s", req.Action)
			licenseAudit.record("license_validate", req.Actor, req.Role, cfg.License.Path, req.Note, "failed", err.Error())
			return api.LicenseActionResult{
				Status:      "failed",
				Message:     err.Error(),
				ValidatedAt: time.Now().UTC().Format(time.RFC3339),
			}, err
		}
		summary := inspectLicense()
		validatedAt := time.Now().UTC().Format(time.RFC3339)
		summary.LastValidatedAt = validatedAt
		if summary.Present && !summary.Revoked && (!summary.Expired || summary.InGracePeriod) && (summary.SignaturePresent == false || summary.SignatureVerified) && (summary.LastError == "" || summary.InGracePeriod) {
			summary.LastError = ""
			message := "license file validated"
			if summary.InGracePeriod {
				message = "license validated within grace period"
			}
			licenseAudit.record("license_validate", req.Actor, req.Role, summary.Path, req.Note, "validated", message)
			if auditStore != nil {
				_ = auditStore.Log(audit.Entry{
					Category: audit.CatAdmin,
					Severity: "INFO",
					Message:  message,
					Source:   "license",
					Details: map[string]interface{}{
						"path":       summary.Path,
						"actor":      req.Actor,
						"role":       req.Role,
						"note":       req.Note,
						"size_bytes": summary.SizeBytes,
						"license_id": summary.LicenseID,
						"grace":      summary.InGracePeriod,
					},
				})
			}
		} else {
			licenseAudit.record("license_validate", req.Actor, req.Role, summary.Path, req.Note, "failed", summary.LastError)
			if auditStore != nil {
				_ = auditStore.Log(audit.Entry{
					Category: audit.CatAdmin,
					Severity: "WARNING",
					Message:  "License validation failed",
					Source:   "license",
					Details: map[string]interface{}{
						"path":  summary.Path,
						"actor": req.Actor,
						"role":  req.Role,
						"note":  req.Note,
						"error": summary.LastError,
					},
				})
			}
		}
		summary.History = licenseAudit.snapshot()
		licenseSummaryState.update(summary)
		result := api.LicenseActionResult{
			Status:            "validated",
			Message:           "license file validated",
			ValidatedAt:       validatedAt,
			ExpiresAt:         summary.ExpiresAt,
			GracePeriodDays:   summary.GracePeriodDays,
			InGracePeriod:     summary.InGracePeriod,
			Revoked:           summary.Revoked,
			SignatureVerified: summary.SignatureVerified,
		}
		if summary.InGracePeriod {
			result.Message = "license validated within grace period"
		}
		if !summary.Present || summary.Revoked || (summary.Expired && !summary.InGracePeriod) || (summary.SignaturePresent && !summary.SignatureVerified) || (summary.LastError != "" && !summary.InGracePeriod) {
			result.Status = "failed"
			result.Message = summary.LastError
			if result.Message == "" && summary.Expired {
				result.Message = "license has expired"
			}
			return result, fmt.Errorf("%s", result.Message)
		}
		return result, nil
	})
	apiServer.SetUpgradeReadinessFunc(func() api.UpgradeReadiness {
		cached := upgradeSummaryState.snapshot()
		summary := inspectUpgradePackage(
			firstNonEmpty(strings.TrimSpace(cached.PackagePath), strings.TrimSpace(cfg.Upgrade.PackagePath)),
			firstNonEmpty(strings.TrimSpace(cached.ExpectedSHA256), strings.TrimSpace(cfg.Upgrade.ExpectedSHA256)),
			firstNonEmpty(strings.TrimSpace(cached.SignaturePath), strings.TrimSpace(cfg.Upgrade.SignaturePath)),
			strings.TrimSpace(cfg.Upgrade.SigningKey),
			strings.TrimSpace(cfg.Upgrade.PublicKeyPath),
			firstNonEmpty(strings.TrimSpace(cached.RollbackPlan), strings.TrimSpace(cfg.Upgrade.RollbackPlan)),
		)
		summary.DownloadURL = firstNonEmpty(strings.TrimSpace(cached.DownloadURL), strings.TrimSpace(cfg.Upgrade.DownloadURL))
		summary.LastAction = cached.LastAction
		summary.LastActor = cached.LastActor
		summary.LastActionAt = cached.LastActionAt
		summary.LastNote = cached.LastNote
		summary.LastVerifiedAt = cached.LastVerifiedAt
		summary.History = upgradeAudit.snapshot()
		upgradeSummaryState.update(summary)
		return summary
	})
	apiServer.SetUpgradeActionFunc(func(req api.UpgradeActionRequest) (api.UpgradeActionResult, error) {
		action := strings.ToLower(strings.TrimSpace(req.Action))
		if action == "" {
			action = "check"
		}
		if action != "check" && action != "record" && action != "preflight" && action != "download" {
			err := fmt.Errorf("unsupported upgrade action: %s", req.Action)
			upgradeAudit.record("upgrade_action", req.Actor, req.Role, version.String(), req.Note, "failed", err.Error())
			return api.UpgradeActionResult{
				Status:      "failed",
				Message:     err.Error(),
				PerformedAt: time.Now().UTC().Format(time.RFC3339),
			}, err
		}
		cached := upgradeSummaryState.snapshot()
		downloadURL := firstNonEmpty(strings.TrimSpace(req.DownloadURL), strings.TrimSpace(cached.DownloadURL), strings.TrimSpace(cfg.Upgrade.DownloadURL))
		packagePath := firstNonEmpty(strings.TrimSpace(req.PackagePath), strings.TrimSpace(cached.PackagePath), strings.TrimSpace(cfg.Upgrade.PackagePath))
		expectedSHA256 := firstNonEmpty(strings.TrimSpace(req.ExpectedSHA256), strings.TrimSpace(cached.ExpectedSHA256), strings.TrimSpace(cfg.Upgrade.ExpectedSHA256))
		signaturePath := firstNonEmpty(strings.TrimSpace(req.SignaturePath), strings.TrimSpace(cached.SignaturePath), strings.TrimSpace(cfg.Upgrade.SignaturePath))
		rollbackPlan := firstNonEmpty(strings.TrimSpace(req.RollbackPlan), strings.TrimSpace(cached.RollbackPlan), strings.TrimSpace(cfg.Upgrade.RollbackPlan))
		performedAt := time.Now().UTC().Format(time.RFC3339)
		message := "upgrade readiness check recorded"
		status := "recorded"
		if action == "download" || action == "preflight" {
			if downloadURL != "" && packagePath != "" {
				if err := downloadToPath(downloadURL, packagePath); err != nil {
					return api.UpgradeActionResult{
						Status:      "failed",
						Message:     err.Error(),
						DownloadURL: downloadURL,
						PerformedAt: performedAt,
					}, err
				}
				if signaturePath == "" && packagePath != "" {
					signaturePath = packagePath + ".sig"
				}
				if strings.TrimSpace(cfg.Upgrade.PublicKeyPath) != "" && signaturePath != "" {
					_ = downloadToPath(downloadURL+".sig", signaturePath)
				}
			}
		}
		summary := inspectUpgradePackage(packagePath, expectedSHA256, signaturePath, strings.TrimSpace(cfg.Upgrade.SigningKey), strings.TrimSpace(cfg.Upgrade.PublicKeyPath), rollbackPlan)
		if action == "record" {
			message = "upgrade plan note recorded"
		} else if action == "download" {
			message = "upgrade artifact downloaded"
			status = "downloaded"
		} else if action == "preflight" {
			summary.LastVerifiedAt = performedAt
			if summary.PreflightReady {
				message = "upgrade preflight passed"
				status = "ready"
			} else {
				status = "failed"
				if summary.LastError != "" {
					message = summary.LastError
				} else if !summary.RollbackReady {
					message = "rollback plan not configured"
				} else {
					message = "upgrade preflight failed"
				}
			}
		} else {
			summary.LastVerifiedAt = performedAt
			if !summary.PackagePresent || !summary.PackageVerified || (summary.SignaturePresent && !summary.SignatureVerified) || summary.LastError != "" {
				status = "failed"
				if summary.LastError != "" {
					message = summary.LastError
				}
			} else {
				if summary.SignaturePresent {
					message = "upgrade package and signature verified"
				} else {
					message = "upgrade package verified"
				}
			}
		}
		upgradeAudit.record("upgrade_"+action, req.Actor, req.Role, version.String(), req.Note, status, message)
		if auditStore != nil {
			severity := "INFO"
			if status == "failed" {
				severity = "WARNING"
			}
			_ = auditStore.Log(audit.Entry{
				Category: audit.CatAdmin,
				Severity: severity,
				Message:  message,
				Source:   "upgrade",
				Details: map[string]interface{}{
					"action":          action,
					"actor":           req.Actor,
					"role":            req.Role,
					"note":            req.Note,
					"current_version": version.String(),
					"package_path":    packagePath,
					"expected_sha256": expectedSHA256,
					"package_sha256":  summary.PackageSHA256,
					"signature_path":  signaturePath,
					"signature_ok":    summary.SignatureVerified,
					"rollback_plan":   rollbackPlan,
				},
			})
		}
		summary.UpdatedAt = performedAt
		summary.CurrentVersion = version.String()
		summary.GuidePath = "docs/developer/testing.md"
		summary.PackagePath = packagePath
		summary.DownloadURL = downloadURL
		summary.ExpectedSHA256 = expectedSHA256
		summary.SignaturePath = signaturePath
		summary.RollbackPlan = rollbackPlan
		summary.LastAction = action
		summary.LastActor = req.Actor
		summary.LastActionAt = performedAt
		summary.LastNote = req.Note
		summary.History = upgradeAudit.snapshot()
		upgradeSummaryState.update(summary)
		return api.UpgradeActionResult{
			Status:            status,
			Message:           message,
			PackagePath:       summary.PackagePath,
			DownloadURL:       summary.DownloadURL,
			PackageSHA256:     summary.PackageSHA256,
			PackageVerified:   summary.PackageVerified,
			SignaturePath:     summary.SignaturePath,
			SignatureVerified: summary.SignatureVerified,
			PreflightReady:    summary.PreflightReady,
			PerformedAt:       performedAt,
		}, nil
	})
	apiServer.SetPolicyCenterFunc(func() api.PolicyCenter {
		if mgmtServer == nil {
			rules := 0
			ruleIDs := []string{}
			if apt != nil {
				ruleIDs = apt.SigmaRuleIDs()
				rules = len(ruleIDs)
			}
			now := time.Now().UTC().Format(time.RFC3339)
			base := api.PolicySummary{
				Version:      1,
				State:        "published",
				UpdatedAt:    now,
				PublishedAt:  now,
				ActiveRules:  rules,
				SigmaRuleIDs: ruleIDs,
			}
			draft := base
			draft.State = "draft"
			return api.PolicyCenter{
				UpdatedAt: now,
				Current:   base,
				Draft:     draft,
				History:   []api.PolicySummary{base},
				Actions:   policyAudit.snapshot(),
			}
		}
		snapshot := mgmtServer.PolicyCenter()
		center := api.PolicyCenter{
			UpdatedAt: snapshot.UpdatedAt.UTC().Format(time.RFC3339),
			Current:   toAPIPolicySummary(snapshot.Current),
			Draft:     toAPIPolicySummary(snapshot.Draft),
			History:   make([]api.PolicySummary, 0, len(snapshot.History)),
			Actions:   policyAudit.snapshot(),
		}
		for _, item := range snapshot.History {
			center.History = append(center.History, toAPIPolicySummary(item))
		}
		return center
	})
	apiServer.SetPolicyActionFunc(func(req api.PolicyActionRequest) (api.PolicySummary, error) {
		if mgmtServer == nil {
			err := fmt.Errorf("mgmt server not available")
			policyAudit.record(req.Action, req.Actor, req.Role, "", req.Notes, "failed", err.Error())
			return api.PolicySummary{}, err
		}
		switch strings.ToLower(strings.TrimSpace(req.Action)) {
		case "publish":
			summary := toAPIPolicySummary(mgmtServer.PublishPolicy(req.Notes))
			policyAudit.record(req.Action, req.Actor, req.Role, fmt.Sprintf("v%d", summary.Version), req.Notes, "published", "policy published")
			return summary, nil
		case "rollback":
			revision, err := mgmtServer.RollbackPolicy(req.TargetVersion, req.Notes)
			if err != nil {
				policyAudit.record(req.Action, req.Actor, req.Role, fmt.Sprintf("v%d", req.TargetVersion), req.Notes, "failed", err.Error())
				return api.PolicySummary{}, err
			}
			summary := toAPIPolicySummary(revision)
			policyAudit.record(req.Action, req.Actor, req.Role, fmt.Sprintf("v%d", summary.Version), req.Notes, "rolled_back", fmt.Sprintf("policy rolled back from v%d", req.TargetVersion))
			return summary, nil
		default:
			err := fmt.Errorf("unknown policy action %q", req.Action)
			policyAudit.record(req.Action, req.Actor, req.Role, "", req.Notes, "failed", err.Error())
			return api.PolicySummary{}, err
		}
	})
	apiServer.SetAlertWorkflowFunc(func(status, assignee string) api.AlertWorkflow {
		snapshot := alertWorkflow.Snapshot(status, assignee)
		items := make([]api.AlertWorkflowItem, 0, len(snapshot.Alerts))
		for _, item := range snapshot.Alerts {
			items = append(items, toAPIAlertWorkflowItem(item))
		}
		return api.AlertWorkflow{
			UpdatedAt: snapshot.UpdatedAt,
			Summary: api.AlertWorkflowSummary{
				Total:      snapshot.Summary.Total,
				Open:       snapshot.Summary.Open,
				Assigned:   snapshot.Summary.Assigned,
				Suppressed: snapshot.Summary.Suppressed,
				Closed:     snapshot.Summary.Closed,
			},
			Alerts:  items,
			History: workflowAudit.snapshot(),
		}
	})
	apiServer.SetAlertWorkflowActionFunc(func(req api.AlertWorkflowActionRequest) (api.AlertWorkflowItem, error) {
		updated, err := alertWorkflow.Update(alertflow.UpdateRequest{
			Action:   req.Action,
			AlertID:  req.AlertID,
			Assignee: req.Assignee,
			Duration: req.Duration,
			Note:     req.Note,
		})
		if err != nil {
			workflowAudit.record(req.Action, req.Actor, req.Role, req.AlertID, req.Note, "failed", err.Error())
			return api.AlertWorkflowItem{}, err
		}
		workflowAudit.record(req.Action, req.Actor, req.Role, updated.ID, req.Note, string(updated.Status), alertWorkflowAuditMessage(updated, req.Action))
		return toAPIAlertWorkflowItem(updated), nil
	})
	apiServer.SetNotifyDeliveryFunc(func() api.NotifyDeliveryCenter {
		snapshot := notifyMgrSnapshot(notifyMgr)
		recent := make([]api.NotifyDeliveryRecord, 0, len(snapshot.Recent))
		for _, item := range snapshot.Recent {
			recent = append(recent, toAPINotifyDeliveryRecord(item))
		}
		deadLetters := make([]api.NotifyDeliveryRecord, 0, len(snapshot.DeadLetters))
		for _, item := range snapshot.DeadLetters {
			deadLetters = append(deadLetters, toAPINotifyDeliveryRecord(item))
		}
		return api.NotifyDeliveryCenter{
			UpdatedAt: snapshot.UpdatedAt,
			Summary: api.NotifyDeliverySummary{
				Delivered:  snapshot.Summary.Delivered,
				Retrying:   snapshot.Summary.Retrying,
				DeadLetter: snapshot.Summary.DeadLetter,
			},
			Recent:      recent,
			DeadLetters: deadLetters,
			History:     deliveryAudit.snapshot(),
		}
	})
	apiServer.SetNotifyDeliveryActionFunc(func(req api.NotifyDeliveryActionRequest) (api.NotifyDeliveryActionResult, error) {
		action := strings.ToLower(strings.TrimSpace(req.Action))
		var out api.NotifyDeliveryActionResult
		var err error
		switch action {
		case "replay":
			if notifyMgr == nil {
				err = fmt.Errorf("notify manager not available")
				break
			}
			deadLetterBeforeReplay, _ := notifyMgr.DeadLetterRecord(strings.TrimSpace(req.DeliveryID))
			result, err := notifyMgr.ReplayDeadLetter(strings.TrimSpace(req.DeliveryID))
			record := toAPINotifyDeliveryRecord(result.Record)
			out = api.NotifyDeliveryActionResult{
				Status:      "replayed",
				Message:     "dead letter replayed successfully",
				Record:      &record,
				PerformedAt: result.UpdatedAt,
			}
			if err != nil {
				out.Status = "replay_failed"
				out.Message = err.Error()
			} else if ticketClient != nil {
				if deadLetterBeforeReplay.Ticket != nil {
					commentErr := syncTicketComment(ticketClient, ticketing.Issue{
						Provider: deadLetterBeforeReplay.Ticket.Provider,
						Key:      deadLetterBeforeReplay.Ticket.Key,
						URL:      deadLetterBeforeReplay.Ticket.URL,
					}, replayCommentFromResult(req, result.Record))
					if commentErr != nil {
						out.Message += "; ticket comment sync failed: " + commentErr.Error()
					}
				}
			}
		case "replay_all":
			if notifyMgr == nil {
				err = fmt.Errorf("notify manager not available")
				break
			}
			batch := notifyMgr.ReplayAllDeadLetters()
			records := make([]api.NotifyDeliveryRecord, 0, len(batch.Records))
			for _, item := range batch.Records {
				records = append(records, toAPINotifyDeliveryRecord(item))
			}
			status := "replayed_batch"
			message := fmt.Sprintf("replayed %d dead letter(s)", batch.Succeeded)
			if batch.Failed > 0 {
				status = "replay_batch_partial"
				message = fmt.Sprintf("replayed %d dead letter(s), %d failed", batch.Succeeded, batch.Failed)
			}
			out = api.NotifyDeliveryActionResult{
				Status:      status,
				Message:     message,
				Records:     records,
				Processed:   batch.Processed,
				Succeeded:   batch.Succeeded,
				Failed:      batch.Failed,
				PerformedAt: batch.UpdatedAt,
			}
		case "create_ticket":
			if notifyMgr == nil {
				err = fmt.Errorf("notify manager not available")
				break
			}
			if ticketClient == nil {
				err = fmt.Errorf("ticketing client not configured")
				break
			}
			record, ok := notifyMgr.DeadLetterRecord(strings.TrimSpace(req.DeliveryID))
			if !ok {
				err = fmt.Errorf("dead letter %q not found", req.DeliveryID)
				break
			}
			out, err = createTicketForDelivery(req, notifyMgr, ticketClient, record)
		case "create_ticket_all":
			if notifyMgr == nil {
				err = fmt.Errorf("notify manager not available")
				break
			}
			if ticketClient == nil {
				err = fmt.Errorf("ticketing client not configured")
				break
			}
			records := notifyMgr.DeadLetterRecords()
			out = api.NotifyDeliveryActionResult{
				Status:      "ticket_batch_created",
				Processed:   len(records),
				Records:     make([]api.NotifyDeliveryRecord, 0, len(records)),
				PerformedAt: time.Now().UTC().Format(time.RFC3339),
			}
			for _, record := range records {
				result, err := createTicketForDelivery(req, notifyMgr, ticketClient, record)
				if result.Record != nil {
					out.Records = append(out.Records, *result.Record)
				}
				if err != nil {
					out.Failed++
					continue
				}
				switch result.Status {
				case "ticket_exists":
					out.Skipped++
				default:
					out.Succeeded++
				}
			}
			if out.Failed > 0 {
				out.Status = "ticket_batch_partial"
			}
			out.Message = fmt.Sprintf(
				"processed %d dead letter(s): %d ticket(s) created, %d skipped, %d failed",
				out.Processed,
				out.Succeeded,
				out.Skipped,
				out.Failed,
			)
			out.PerformedAt = time.Now().UTC().Format(time.RFC3339)
		default:
			err = fmt.Errorf("unknown delivery action %q", req.Action)
		}
		deliveryAudit.record(req, out, err)
		return out, err
	})

	go func() {
		if cfg.TLS.Enable {
			logx.System().Info("api server starting with TLS", "addr", cfg.API.REST)
			if err := apiServer.StartTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
				logx.System().Error("api server error", "error", err)
			}
		} else {
			logx.System().Info("api server starting", "addr", cfg.API.REST)
			if err := apiServer.Start(); err != nil {
				logx.System().Error("api server error", "error", err)
			}
		}
	}()

	// ── gRPC management server (mTLS) ──────────────────
	if cfg.TLS.Enable {
		mgmtCfg := &mgmt.ServerConfig{
			ListenAddr:        cfg.API.GRPC,
			CertFile:          cfg.TLS.CertFile,
			KeyFile:           cfg.TLS.KeyFile,
			CAFile:            cfg.TLS.CAFile,
			EnableTLS:         true,
			RequireClientCert: true,
		}
		mgmtServer, err = mgmt.NewServer(mgmtCfg)
		if err != nil {
			logx.System().Error("mgmt server init failed", "error", err)
			os.Exit(1)
		}
		mgmtServer.SetController(bpfLoader.Ctrl)
		mgmtServer.SetAnalyzer(apt)
		mgmtServer.StartAlertForwarder(apt.AlertCh)
		if err := mgmtServer.Start(); err != nil {
			logx.System().Error("mgmt server start failed", "error", err)
			os.Exit(1)
		}
		defer mgmtServer.Stop()
		logx.System().Info("mgmt gRPC server started", "addr", cfg.API.GRPC, "tls", true)
	}

	// ── Real-time alert persistence (NDJSON) ──────────────
	alertPath := filepath.Join(cfg.Output.Dir, "alerts.ndjson")
	alertFile, err := os.OpenFile(alertPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logx.System().Error("alert file open failed", "error", err)
	}
	var alertEnc *json.Encoder
	if alertFile != nil {
		alertEnc = json.NewEncoder(alertFile)
		defer alertFile.Close()
	}

	// ── Signals: shutdown (SIGINT/SIGTERM) + reload (SIGHUP) ──
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	logx.System().Info("daemon started",
		"events", "RingBuf → Pipeline → Graph → Analyzer",
		"storage", "Hot nodes (LRU cache) + Cold nodes & edges (RocksDB)",
		"merge", "5s sliding window dedup",
		"backpressure", "auto at 70% memory",
	)

	eventCount := 0
	metricsTicker := time.NewTicker(15 * time.Second)
	defer metricsTicker.Stop()

loop:
	for {
		select {
		case evt := <-eventCh:
			pipe.AddEvent(evt)
			if err := writer.Write(evt); err != nil {
				logx.System().Error("event write error", "error", err)
				storeHealthy = false
			} else {
				storeHealthy = true
			}
			eventCount++
			eventsIngested = uint64(eventCount)

			// Track dropped events via backpressure signal
			select {
			case <-pipe.PauseCh():
				eventsDropped++
			default:
			}

			// Update metrics
			metrics.EventsIngested.Inc()
			metrics.PipelineEventsProcessed.Inc()

		case err := <-errCh:
			logx.System().Error("collector error", "error", err)

		case al := <-apt.AlertCh:
			logx.System().Warn("alert triggered", "alert", fmt.Sprintf("%s", al))
			logx.Audit().Warn("security_alert", "alert", fmt.Sprintf("%s", al))
			if alertEnc != nil {
				if err := alertEnc.Encode(al); err != nil {
					logx.System().Error("alert write failed", "error", err)
				}
			}
			workflowAlert, deliver := alertWorkflow.Ingest(notify.Alert{
				ID:        al.AlertNodeID,
				Timestamp: al.DetectedAt,
				Severity:  notify.Severity(al.Severity.String()),
				Pattern:   string(al.Pattern),
				Headline:  al.Headline,
				Reason:    al.Reason,
				Source:    "analyzer",
			})
			if notifyMgr != nil && deliver {
				notifyMgr.Send(toNotifyAlert(workflowAlert))
			}

		case <-pipe.PauseCh():
			logx.System().Warn("backpressure: pausing ring buffer read")
			pipelineHealthy = false
			metrics.PipelineBackpressure.Inc()
			select {
			case <-pipe.ResumeCh():
				logx.System().Info("backpressure: resuming ring buffer read")
				pipelineHealthy = true
			case <-sigCh:
				break loop
			case <-time.After(10 * time.Second):
				logx.System().Warn("backpressure: forced resume after timeout")
				pipelineHealthy = true
			}

		case <-metricsTicker.C:
			// Periodic system metric updates
			updateSystemMetrics(startTime, eventsDropped)

			// systemd watchdog heartbeat
			sdNotifyWatchdog()

		case sig := <-sigCh:
			if sig == syscall.SIGQUIT {
				logx.System().Info("SIGQUIT received, dumping goroutine stacks")
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				logx.System().Info("goroutine dump", "stack", string(buf[:n]))
				continue
			}
			if sig == syscall.SIGHUP {
				logx.System().Info("SIGHUP received, reloading config")
				newCfg, err := config.Load(*configPath)
				if err != nil {
					logx.System().Error("config reload failed", "error", err)
					continue
				}
				// Reload analyzer config (atomic pointer swap)
				newAptCfg := &analyzer.Config{
					ScanInterval:       time.Duration(newCfg.Analyzer.ScanInterval.Duration),
					DeepTaintThreshold: newCfg.Analyzer.DeepTaintThreshold,
					Quiet:              newCfg.Analyzer.Quiet,
				}
				for _, p := range newCfg.Analyzer.EnablePatterns {
					newAptCfg.EnablePatterns = append(newAptCfg.EnablePatterns, analyzer.PatternID(p))
				}
				apt.ReloadConfig(newAptCfg)

				// Reload taint seeds
				if newCfg.TaintSecrets.UntrustedComms != nil || newCfg.TaintSecrets.NetworkTools != nil {
					untrusted := make(map[string]bool)
					for _, c := range newCfg.TaintSecrets.UntrustedComms {
						untrusted[c] = true
					}
					network := make(map[string]bool)
					for _, c := range newCfg.TaintSecrets.NetworkTools {
						network[c] = true
					}
					analyzer.ReloadTaintSeeds(untrusted, network, newCfg.TaintSecrets.SensitivePaths)
				}

				// Update log level if changed
				if newCfg.Log.Level != cfg.Log.Level {
					logx.Init(newCfg.Log.Level, newCfg.Log.Format)
				}

				cfg = newCfg
				logx.System().Info("config reloaded successfully")
				continue
			}
			logx.System().Info("shutdown signal received", "signal", fmt.Sprintf("%v", sig))
			fmt.Printf("\nsignal %v, shutting down...\n", sig)
			break loop
		}
	}

	// ── Final report ────────────────────────────────────
	graphStats := graph.Stats()
	alerts := apt.Alerts()
	pipeStats := pipe.Stats()

	logx.System().Info("shutdown complete",
		"events_processed", eventCount,
		"graph_nodes", graphStats.Nodes,
		"graph_edges", graphStats.Edges,
		"alerts", len(alerts),
	)

	if cache, ok := pipeStats["cache"].(map[string]interface{}); ok {
		logx.System().Info("pipeline stats", "cache_size", cache["size"])
	}

	// ── Serialize provenance graph ──────────────────────
	outDir := cfg.Output.Dir
	if outDir == "" {
		outDir = "."
	}
	os.MkdirAll(outDir, 0755)

	jsonPath := filepath.Join(outDir, "provenance.json")
	f, err := os.Create(jsonPath)
	if err == nil {
		defer f.Close()
		if err := graph.SerializeJSON(f); err != nil {
			logx.System().Error("JSON serialize error", "error", err)
		} else {
			logx.System().Info("saved graph JSON", "path", jsonPath)
		}
	}

	graphmlPath := filepath.Join(outDir, "provenance.graphml")
	f2, err := os.Create(graphmlPath)
	if err == nil {
		defer f2.Close()
		if err := graph.SerializeGraphML(f2); err != nil {
			logx.System().Error("GraphML error", "error", err)
		} else {
			logx.System().Info("saved graph GraphML", "path", graphmlPath)
		}
	}

}

// writePIDFile writes the daemon PID to /var/run/providaptd.pid.
func writePIDFile() {
	if err := os.MkdirAll(filepath.Dir(pidFile), 0755); err != nil {
		logx.System().Error("pidfile dir error", "error", err)
		return
	}
	if err := ioutil.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
		logx.System().Error("pidfile write error", "error", err)
	}
}

// updateSystemMetrics pushes system-level Prometheus metrics.
func updateSystemMetrics(startTime time.Time, eventsDropped uint64) {
	metrics.UptimeSeconds.Set(time.Since(startTime).Seconds())
	metrics.EventsDroppedTotal.Add(float64(eventsDropped))

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	metrics.MemoryUsageBytes.Set(float64(m.Alloc))

	// Approximate CPU: goroutines as a proxy
	metrics.CPUUsageRatio.Set(float64(runtime.NumGoroutine()) / 1000.0)
}

// healthStatus returns "healthy" when all subsystems are OK, else "unhealthy".
func healthStatus(pipelineHealthy, storeHealthy bool) string {
	if pipelineHealthy && storeHealthy {
		return "healthy"
	}
	return "unhealthy"
}

func toAPIPolicySummary(revision mgmt.PolicyRevision) api.PolicySummary {
	summary := api.PolicySummary{
		Version:          revision.Version,
		State:            revision.State,
		Notes:            revision.Notes,
		ActiveRules:      revision.ActiveRules,
		SigmaRuleIDs:     append([]string(nil), revision.SigmaRuleIDs...),
		WhitelistCount:   revision.WhitelistCount,
		TaintSourceCount: revision.TaintSourceCount,
	}
	if !revision.UpdatedAt.IsZero() {
		summary.UpdatedAt = revision.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if !revision.PublishedAt.IsZero() {
		summary.PublishedAt = revision.PublishedAt.UTC().Format(time.RFC3339)
	}
	return summary
}

func toAPIAlertWorkflowItem(item alertflow.Alert) api.AlertWorkflowItem {
	out := api.AlertWorkflowItem{
		ID:       item.ID,
		Severity: item.Severity,
		Pattern:  item.Pattern,
		Headline: item.Headline,
		Reason:   item.Reason,
		Source:   item.Source,
		Status:   string(item.Status),
		Assignee: item.Assignee,
		Count:    item.Count,
		Note:     item.Note,
		Details:  cloneStringMap(item.Details),
	}
	if !item.FirstSeen.IsZero() {
		out.FirstSeen = item.FirstSeen.UTC().Format(time.RFC3339)
	}
	if !item.LastSeen.IsZero() {
		out.LastSeen = item.LastSeen.UTC().Format(time.RFC3339)
	}
	if !item.LastNotifiedAt.IsZero() {
		out.LastNotifiedAt = item.LastNotifiedAt.UTC().Format(time.RFC3339)
	}
	if !item.SilenceUntil.IsZero() {
		out.SilenceUntil = item.SilenceUntil.UTC().Format(time.RFC3339)
	}
	return out
}

func toNotifyAlert(item alertflow.Alert) notify.Alert {
	return notify.Alert{
		ID:        item.ID,
		Timestamp: item.LastSeen,
		Severity:  notify.Severity(item.Severity),
		Pattern:   item.Pattern,
		Headline:  item.Headline,
		Reason:    item.Reason,
		Source:    item.Source,
		Details:   cloneStringMap(item.Details),
	}
}

func notifyMgrSnapshot(mgr *notify.Manager) notify.DeliverySnapshot {
	if mgr == nil {
		return notify.DeliverySnapshot{
			UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
			Recent:      []notify.DeliveryRecord{},
			DeadLetters: []notify.DeliveryRecord{},
		}
	}
	return mgr.DeliverySnapshot()
}

func toAPINotifyDeliveryRecord(item notify.DeliveryRecord) api.NotifyDeliveryRecord {
	out := api.NotifyDeliveryRecord{
		ID:          item.ID,
		Notifier:    item.Notifier,
		AlertID:     item.AlertID,
		Pattern:     item.Pattern,
		Severity:    string(item.Severity),
		Status:      string(item.Status),
		Attempt:     item.Attempt,
		MaxAttempts: item.MaxAttempts,
		Error:       item.Error,
	}
	if !item.LastAttemptAt.IsZero() {
		out.LastAttemptAt = item.LastAttemptAt.UTC().Format(time.RFC3339)
	}
	if item.Ticket != nil {
		out.TicketKey = item.Ticket.Key
		out.TicketURL = item.Ticket.URL
		out.TicketType = item.Ticket.Provider
	}
	return out
}

func createTicketForDelivery(req api.NotifyDeliveryActionRequest, notifyMgr *notify.Manager, ticketClient ticketing.Client, record notify.DeliveryRecord) (api.NotifyDeliveryActionResult, error) {
	if record.Ticket != nil {
		apiRecord := toAPINotifyDeliveryRecord(record)
		return api.NotifyDeliveryActionResult{
			Status:      "ticket_exists",
			Message:     "ticket already linked to dead letter",
			Record:      &apiRecord,
			TicketKey:   record.Ticket.Key,
			TicketURL:   record.Ticket.URL,
			TicketType:  record.Ticket.Provider,
			PerformedAt: record.Ticket.LinkedAt.UTC().Format(time.RFC3339),
		}, nil
	}
	issue, err := ticketClient.CreateIssue(ticketRequestFromDelivery(record))
	if err != nil {
		return api.NotifyDeliveryActionResult{}, err
	}
	commentErr := syncTicketComment(ticketClient, issue, createTicketCommentFromDelivery(req, record))
	updatedRecord, err := notifyMgr.SetTicketReference(record.ID, notify.TicketReference{
		Provider:    issue.Provider,
		Key:         issue.Key,
		URL:         issue.URL,
		LinkedAt:    issue.CreatedAt,
		Idempotency: "delivery:" + record.ID,
	})
	if err != nil {
		return api.NotifyDeliveryActionResult{}, err
	}
	apiRecord := toAPINotifyDeliveryRecord(updatedRecord)
	return api.NotifyDeliveryActionResult{
		Status:      "ticket_created",
		Message:     appendCommentSyncMessage("delivery issue escalated to ticketing", commentErr),
		Record:      &apiRecord,
		TicketKey:   issue.Key,
		TicketURL:   issue.URL,
		TicketType:  issue.Provider,
		PerformedAt: issue.CreatedAt.UTC().Format(time.RFC3339),
	}, nil
}

func syncTicketComment(ticketClient ticketing.Client, issue ticketing.Issue, comment string) error {
	if ticketClient == nil || strings.TrimSpace(comment) == "" {
		return nil
	}
	return ticketClient.AddComment(issue, comment)
}

func appendCommentSyncMessage(message string, err error) string {
	if err == nil {
		return message + "; ticket comment synced"
	}
	return message + "; ticket comment sync failed: " + err.Error()
}

func createTicketCommentFromDelivery(req api.NotifyDeliveryActionRequest, record notify.DeliveryRecord) string {
	base := fmt.Sprintf(
		"ProvidAPT escalated this dead letter.\n\nActor: %s\nRole: %s\nDelivery ID: %s\nPattern: %s\nSeverity: %s\nNotifier: %s\nAttempt: %d/%d\nError: %s",
		fallbackActionActor(req),
		fallbackActionRole(req),
		record.ID,
		record.Pattern,
		record.Severity,
		record.Notifier,
		record.Attempt,
		record.MaxAttempts,
		record.Error,
	)
	if strings.TrimSpace(req.Note) != "" {
		base += "\nOperator note: " + strings.TrimSpace(req.Note)
	}
	return base
}

func replayCommentFromResult(req api.NotifyDeliveryActionRequest, record notify.DeliveryRecord) string {
	status := "replayed"
	if record.Status == notify.DeliveryStatusDeadLetter {
		status = "replay failed"
	}
	base := fmt.Sprintf(
		"ProvidAPT %s this delivery notification.\n\nActor: %s\nRole: %s\nDelivery ID: %s\nPattern: %s\nStatus: %s\nAttempt: %d/%d\nError: %s",
		status,
		fallbackActionActor(req),
		fallbackActionRole(req),
		record.ID,
		record.Pattern,
		record.Status,
		record.Attempt,
		record.MaxAttempts,
		record.Error,
	)
	if strings.TrimSpace(req.Note) != "" {
		base += "\nOperator note: " + strings.TrimSpace(req.Note)
	}
	return base
}

func alertWorkflowAuditMessage(item alertflow.Alert, action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "assign":
		if strings.TrimSpace(item.Assignee) != "" {
			return "alert assigned to " + item.Assignee
		}
		return "alert assignment updated"
	case "silence":
		if !item.SilenceUntil.IsZero() {
			return "alert silenced until " + item.SilenceUntil.UTC().Format(time.RFC3339)
		}
		return "alert silenced"
	case "unsilence":
		return "alert unsilenced"
	case "close":
		return "alert closed"
	case "reopen":
		return "alert reopened"
	default:
		return "alert workflow updated"
	}
}

func fallbackActionActor(req api.NotifyDeliveryActionRequest) string {
	if strings.TrimSpace(req.Actor) == "" {
		return "system"
	}
	return strings.TrimSpace(req.Actor)
}

func fallbackActionRole(req api.NotifyDeliveryActionRequest) string {
	if strings.TrimSpace(req.Role) == "" {
		return api.RoleAdmin
	}
	return strings.TrimSpace(req.Role)
}

func ticketRequestFromDelivery(record notify.DeliveryRecord) ticketing.CreateRequest {
	labels := []string{"providapt", "dead-letter", strings.ToLower(string(record.Severity))}
	metadata := map[string]string{
		"delivery_id":  record.ID,
		"alert_id":     record.AlertID,
		"notifier":     record.Notifier,
		"pattern":      record.Pattern,
		"status":       string(record.Status),
		"attempt":      strconv.Itoa(record.Attempt),
		"max_attempts": strconv.Itoa(record.MaxAttempts),
	}
	if record.Error != "" {
		metadata["error"] = record.Error
	}
	description := fmt.Sprintf(
		"ProvidAPT could not deliver alert notification.\n\nPattern: %s\nSeverity: %s\nNotifier: %s\nAttempt: %d/%d\nError: %s\n",
		record.Pattern,
		record.Severity,
		record.Notifier,
		record.Attempt,
		record.MaxAttempts,
		record.Error,
	)
	return ticketing.CreateRequest{
		Title:       fmt.Sprintf("[ProvidAPT] Dead letter for %s", record.Pattern),
		Description: description,
		Severity:    string(record.Severity),
		Labels:      labels,
		Metadata:    metadata,
	}
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

// sdNotifyWatchdog sends a systemd watchdog heartbeat via NOTIFY_SOCKET.
func sdNotifyWatchdog() {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	// Abstract namespace sockets start with @ — replace with null byte
	if socket[0] == '@' {
		socket = "\x00" + socket[1:]
	}
	addr := &net.UnixAddr{Name: socket, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte("WATCHDOG=1"))
}
