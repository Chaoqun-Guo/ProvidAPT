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
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/analyzer"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	containermon "github.com/Chaoqun-Guo/ProvidAPT/internal/engine/container"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/loader"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/pipeline"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	mgmt "github.com/Chaoqun-Guo/ProvidAPT/internal/policy/mgmt"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/policy/sigma"
	storage "github.com/Chaoqun-Guo/ProvidAPT/internal/storage/format"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/alertflow"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/api"
	mgmtpb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/backup"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/certauth"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/controlplaneha"
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

type systemEnvironment struct {
	Hostname     string
	OS           string
	OSVersion    string
	Kernel       string
	Architecture string
	CPUCount     int
}

type appliedPolicyState struct {
	Version       int    `json:"version"`
	BundleSHA256  string `json:"bundle_sha256,omitempty"`
	BundlePath    string `json:"bundle_path,omitempty"`
	LastAck       string `json:"last_ack,omitempty"`
	LastApplied   string `json:"last_applied,omitempty"`
	SchemaVersion int    `json:"schema_version"`
}

type agentPolicyBundle struct {
	Version       int               `json:"version"`
	State         string            `json:"state"`
	Notes         string            `json:"notes,omitempty"`
	GeneratedAt   time.Time         `json:"generated_at"`
	SigmaRules    map[string]string `json:"sigma_rules,omitempty"`
	WhitelistKeys []string          `json:"whitelist_keys,omitempty"`
	TaintSources  []string          `json:"taint_sources,omitempty"`
}

type agentPolicyClientConfig struct {
	Endpoint  string
	APIKey    string
	BundleDir string
	EnableTLS bool
	CAFile    string
}

func collectSystemEnvironment(hostname string) systemEnvironment {
	env := systemEnvironment{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CPUCount:     runtime.NumCPU(),
	}
	if release, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		env.Kernel = strings.TrimSpace(string(release))
	}
	if osRelease, err := os.ReadFile("/etc/os-release"); err == nil {
		values := map[string]string{}
		for _, line := range strings.Split(string(osRelease), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			values[key] = strings.Trim(value, `"`)
		}
		if prettyName := values["PRETTY_NAME"]; prettyName != "" {
			env.OSVersion = prettyName
		} else if name := values["NAME"]; name != "" {
			env.OSVersion = name
		}
		if id := values["ID"]; id != "" {
			env.OS = id
		}
	}
	return env
}

func stableAgentID(hostname string) string {
	name := strings.TrimSpace(hostname)
	if name == "" {
		name = "unknown"
	}
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		machineID := strings.TrimSpace(string(data))
		if machineID == "" {
			continue
		}
		sum := sha256.Sum256([]byte(machineID))
		return fmt.Sprintf("%s-%s", name, hex.EncodeToString(sum[:])[:8])
	}
	return name
}

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

type backupState struct {
	mu      sync.RWMutex
	summary api.BackupSummary
}

type securityState struct {
	mu      sync.RWMutex
	summary api.SecurityStatus
}

type licenseState struct {
	mu      sync.RWMutex
	summary api.LicenseStatus
}

type upgradeState struct {
	mu      sync.RWMutex
	summary api.UpgradeReadiness
}

type complianceState struct {
	mu      sync.RWMutex
	summary api.ComplianceStatus
}

type approvalStore struct {
	mu      sync.RWMutex
	items   []api.ChangeApproval
	limit   int
	counter uint64
	path    string
}

type persistedApprovals struct {
	Counter uint64               `json:"counter"`
	Items   []api.ChangeApproval `json:"items"`
}

type licenseDocument struct {
	ID                 string `json:"id" yaml:"id"`
	Customer           string `json:"customer" yaml:"customer"`
	Edition            string `json:"edition" yaml:"edition"`
	MaxAgents          int    `json:"max_agents" yaml:"max_agents"`
	MachineFingerprint string `json:"machine_fingerprint" yaml:"machine_fingerprint"`
	IssuedAt           string `json:"issued_at" yaml:"issued_at"`
	ExpiresAt          string `json:"expires_at" yaml:"expires_at"`
	Signature          string `json:"signature" yaml:"signature"`
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

func (s *backupState) snapshot() api.BackupSummary {
	if s == nil {
		return api.BackupSummary{}
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

func (s *backupState) update(summary api.BackupSummary) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.summary = summary
}

func (s *securityState) snapshot() api.SecurityStatus {
	if s == nil {
		return api.SecurityStatus{}
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

func (s *securityState) update(summary api.SecurityStatus) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.summary = summary
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

func (s *complianceState) snapshot() api.ComplianceStatus {
	if s == nil {
		return api.ComplianceStatus{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.summary
	if out.Approvals.Pending != nil {
		pending := make([]api.ChangeApproval, len(out.Approvals.Pending))
		copy(pending, out.Approvals.Pending)
		out.Approvals.Pending = pending
	}
	if out.Approvals.History != nil {
		history := make([]api.ChangeApproval, len(out.Approvals.History))
		copy(history, out.Approvals.History)
		out.Approvals.History = history
	}
	if out.RecommendedActions != nil {
		recommended := make([]string, len(out.RecommendedActions))
		copy(recommended, out.RecommendedActions)
		out.RecommendedActions = recommended
	}
	return out
}

func (s *complianceState) update(summary api.ComplianceStatus) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.summary = summary
}

func newApprovalStore(limit int) *approvalStore {
	if limit <= 0 {
		limit = controlActionHistoryLimit
	}
	return &approvalStore{items: make([]api.ChangeApproval, 0, limit), limit: limit}
}

func newPersistentApprovalStore(path string, limit int) *approvalStore {
	store := newApprovalStore(limit)
	store.path = strings.TrimSpace(path)
	if store.path == "" {
		return store
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		return store
	}
	var persisted persistedApprovals
	if err := json.Unmarshal(data, &persisted); err != nil {
		return store
	}
	store.counter = persisted.Counter
	store.items = append([]api.ChangeApproval(nil), persisted.Items...)
	if len(store.items) > store.limit {
		store.items = store.items[:store.limit]
	}
	return store
}

func (s *approvalStore) saveLocked() error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(persistedApprovals{Counter: s.counter, Items: s.items}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *approvalStore) request(action, target, actor, note string, ttl time.Duration) api.ChangeApproval {
	if s == nil {
		return api.ChangeApproval{}
	}
	id := atomic.AddUint64(&s.counter, 1)
	now := time.Now().UTC()
	item := api.ChangeApproval{
		ID:          fmt.Sprintf("appr-%06d", id),
		Action:      strings.TrimSpace(action),
		Target:      strings.TrimSpace(target),
		Status:      "pending",
		RequestedBy: strings.TrimSpace(actor),
		RequestedAt: now.Format(time.RFC3339),
		Note:        strings.TrimSpace(note),
	}
	if ttl > 0 {
		item.ExpiresAt = now.Add(ttl).Format(time.RFC3339)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	s.items = append([]api.ChangeApproval{item}, s.items...)
	if len(s.items) > s.limit {
		s.items = s.items[:s.limit]
	}
	if err := s.saveLocked(); err != nil {
		log.Printf("[compliance] save approval request: %v", err)
	}
	return item
}

func (s *approvalStore) resolve(id, status, actor, note string) (api.ChangeApproval, bool) {
	if s == nil {
		return api.ChangeApproval{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(time.Now().UTC())
	for i := range s.items {
		if strings.EqualFold(s.items[i].ID, strings.TrimSpace(id)) {
			if s.items[i].Status == "pending" {
				s.items[i].Status = status
				s.items[i].ApprovedBy = strings.TrimSpace(actor)
				s.items[i].ApprovedAt = time.Now().UTC().Format(time.RFC3339)
				if strings.TrimSpace(note) != "" {
					s.items[i].Note = strings.TrimSpace(note)
				}
				if err := s.saveLocked(); err != nil {
					log.Printf("[compliance] save approval resolution: %v", err)
				}
			}
			return s.items[i], true
		}
	}
	return api.ChangeApproval{}, false
}

func (s *approvalStore) status(enabled bool, required []string, ttl string) api.ApprovalStatus {
	status := api.ApprovalStatus{
		Enabled:         enabled,
		RequiredActions: dedupeStrings(required),
		TTL:             strings.TrimSpace(ttl),
		Pending:         []api.ChangeApproval{},
		History:         []api.ChangeApproval{},
	}
	if s == nil {
		return status
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(time.Now().UTC())
	for _, item := range s.items {
		if item.Status == "pending" {
			status.Pending = append(status.Pending, item)
		}
		status.History = append(status.History, item)
	}
	return status
}

func (s *approvalStore) consumeApproved(action, actor string) bool {
	if s == nil {
		return false
	}
	action = strings.TrimSpace(action)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.expireLocked(now)
	for i := range s.items {
		item := s.items[i]
		if item.Status == "approved" && strings.EqualFold(item.Action, action) {
			s.items[i].Status = "used"
			s.items[i].UsedBy = strings.TrimSpace(actor)
			s.items[i].UsedAt = now.Format(time.RFC3339)
			if err := s.saveLocked(); err != nil {
				log.Printf("[compliance] save approval consumption: %v", err)
			}
			return true
		}
	}
	return false
}

func (s *approvalStore) expireLocked(now time.Time) {
	changed := false
	for i := range s.items {
		if s.items[i].Status != "pending" && s.items[i].Status != "approved" {
			continue
		}
		expiresAt := parseTimeOrZero(s.items[i].ExpiresAt)
		if !expiresAt.IsZero() && !expiresAt.After(now) {
			s.items[i].Status = "expired"
			changed = true
		}
	}
	if changed {
		if err := s.saveLocked(); err != nil {
			log.Printf("[compliance] save approval expiration: %v", err)
		}
	}
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
	parts := []string{
		"id=" + strings.TrimSpace(doc.ID),
		"customer=" + strings.TrimSpace(doc.Customer),
		"edition=" + strings.TrimSpace(doc.Edition),
		"machine_fingerprint=" + strings.TrimSpace(doc.MachineFingerprint),
		"issued_at=" + strings.TrimSpace(doc.IssuedAt),
		"expires_at=" + strings.TrimSpace(doc.ExpiresAt),
	}
	if doc.MaxAgents > 0 {
		parts = append(parts, "max_agents="+strconv.Itoa(doc.MaxAgents))
	}
	return strings.Join(parts, "\n")
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

func machineFingerprint() string {
	hostname, _ := os.Hostname()
	parts := []string{
		strings.ToLower(strings.TrimSpace(hostname)),
		runtime.GOOS,
		runtime.GOARCH,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
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

func runUpgradeCommand(command, packagePath, rollbackPlan string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("upgrade command is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.Env = append(os.Environ(),
		"PROVIDAPT_UPGRADE_PACKAGE="+strings.TrimSpace(packagePath),
		"PROVIDAPT_UPGRADE_ROLLBACK_PLAN="+strings.TrimSpace(rollbackPlan),
		"PROVIDAPT_VERSION="+version.String(),
	)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(output), fmt.Errorf("upgrade command timed out")
	}
	return string(output), err
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func parsePositiveDurationOrDefault(value string, fallback time.Duration) time.Duration {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(trimmed)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
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
	if sanityReport.Warnings > 0 {
		logx.System().Warn("sanity checks completed with warnings", "summary", sanityReport.Summary())
	} else {
		logx.System().Info("all sanity checks passed", "summary", sanityReport.Summary())
	}

	// ── eBPF loader ─────────────────────────────────────
	bpfLoader, err := loader.NewWithAudit(cfg, auditStore)
	if err != nil {
		logx.System().Error("loader init failed", "error", err)
		os.Exit(1)
	}
	defer bpfLoader.Close()
	logx.System().Info("socket tracking configured", "attachment_mode", bpfLoader.ModeName(), "hook", "socket_connect")

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

		// Apply runtime capture controls before dropping privileges.
		if cfg.Capture.AutoExcludeNoisy {
			if err := bpfLoader.Ctrl.DefaultExcludes(); err != nil {
				logx.System().Warn("default excludes failed", "error", err)
			}
		}
		for _, pid := range cfg.Capture.ExcludePIDs {
			if err := bpfLoader.Ctrl.ExcludePID(pid); err != nil {
				logx.System().Warn("capture exclude pid failed", "pid", pid, "error", err)
			}
		}
		if excluded, err := bpfLoader.Ctrl.ExcludeComms(cfg.Capture.ExcludeComms); err != nil {
			logx.System().Warn("capture exclude comms failed", "error", err)
		} else if excluded > 0 {
			logx.System().Info("capture exclude comms applied", "count", excluded)
		}
		if excluded, err := bpfLoader.Ctrl.ExcludeCommsExcept(cfg.Capture.IncludeComms); err != nil {
			logx.System().Warn("capture include comms failed", "error", err)
		} else if excluded > 0 {
			logx.System().Info("capture include comms applied", "allowed", len(cfg.Capture.IncludeComms), "excluded", excluded)
		}
		for _, prefix := range cfg.Capture.HotPaths {
			if err := bpfLoader.Ctrl.AddHotPath(prefix); err != nil {
				logx.System().Warn("capture hot path failed", "path", prefix, "error", err)
			}
		}
		controlStats := bpfLoader.Ctrl.Stats()
		logx.System().Info("capture controls configured",
			"auto_exclude_noisy", cfg.Capture.AutoExcludeNoisy,
			"configured_exclude_pids", len(cfg.Capture.ExcludePIDs),
			"configured_exclude_comms", len(cfg.Capture.ExcludeComms),
			"configured_include_comms", len(cfg.Capture.IncludeComms),
			"configured_hot_paths", len(cfg.Capture.HotPaths),
			"pid_whitelist_entries", controlStats["pid_whitelist_entries"],
			"tainted_processes", controlStats["tainted_processes"],
			"active_sample_counters", controlStats["active_sample_counters"],
		)

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
	containerMonitor := containermon.New()
	containerMonitor.Start()
	defer containerMonitor.Stop()
	logx.System().Info("container enrichment configured", "mode", "async_cgroup_monitor")

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
	logx.System().Info("event store configured", "path", pipeCfg.StorePath, "merge_window", pipeCfg.MergeWindow.String())

	// ── APT analyzer ────────────────────────────────────
	aptCfg := analyzer.DefaultConfig()
	aptCfg.ScanInterval = 30 * time.Second
	apt := analyzer.New(graph, aptCfg)
	apt.Start()
	defer apt.Stop()
	logx.System().Info("taint analysis configured", "scan_interval", aptCfg.ScanInterval.String())

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
	backupAudit := newControlActionAuditStore(controlActionHistoryLimit)
	securityAudit := newControlActionAuditStore(controlActionHistoryLimit)
	licenseAudit := newControlActionAuditStore(controlActionHistoryLimit)
	upgradeAudit := newControlActionAuditStore(controlActionHistoryLimit)
	approvalBook := newPersistentApprovalStore(filepath.Join(cfg.Output.Dir, "compliance", "approvals.json"), controlActionHistoryLimit)
	supportState := &supportBundleState{}
	backupSummaryState := &backupState{}
	securitySummaryState := &securityState{}
	licenseSummaryState := &licenseState{}
	upgradeSummaryState := &upgradeState{}
	complianceSummaryState := &complianceState{}
	apiServer.SetAPIAuth(cfg.API.AuthKeys, cfg.API.AuthRoles, cfg.API.AuthIdentities, cfg.API.AuthEnabled)
	apiServer.SetAPIAuthTenants(cfg.API.AuthTenants)
	apiServer.SetAPIAuthPermissions(cfg.API.AuthPermissions)
	apiServer.SetTrustedHeaderAuth(cfg.SSO.TrustedHeaderAuth, cfg.SSO.UserHeader, cfg.SSO.RoleHeader)
	apiServer.SetTrustedTenantHeader(cfg.SSO.TenantHeader)
	apiServer.SetCORSOrigins(cfg.API.CORSOrigins)
	if cfg.API.RateLimitPerSec > 0 {
		apiServer.SetRateLimit(cfg.API.RateLimitPerSec, cfg.API.RateLimitBurst)
	}
	metrics.MustRegister()

	// Health check closure — populated every iteration
	var (
		eventsIngested       uint64
		eventsDropped        uint64
		pipelineHealthy      = true
		storeHealthy         = true
		sanityPassed         = !sanityReport.HasFailures()
		startTime            = time.Now()
		appliedPolicyVersion atomic.Int64
	)
	appliedPolicyStatePath := filepath.Join(cfg.Output.Dir, "applied-policy-state.json")
	if version, err := loadAppliedPolicyVersion(appliedPolicyStatePath); err == nil && version > 0 {
		appliedPolicyVersion.Store(int64(version))
	} else if err != nil {
		logx.System().Warn("load applied policy state failed", "error", err)
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	agentID := stableAgentID(hostname)
	systemEnv := collectSystemEnvironment(hostname)

	telemetryInterval, err := time.ParseDuration(cfg.Telemetry.Interval)
	if err != nil || telemetryInterval <= 0 {
		telemetryInterval = 30 * time.Second
	}
	policyClientCfg := agentPolicyClientConfig{
		Endpoint:  resolvePolicyEndpoint(cfg.Policy.Endpoint, cfg.Telemetry.Endpoint),
		APIKey:    cfg.Policy.APIKey,
		BundleDir: cfg.Policy.BundleDir,
		EnableTLS: cfg.Policy.EnableTLS,
		CAFile:    cfg.Policy.CAFile,
	}
	if policyClientCfg.BundleDir == "" {
		policyClientCfg.BundleDir = filepath.Join(cfg.Output.Dir, "applied-policy-bundles")
	}

	buildTelemetrySummary := func() telemetry.Summary {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		status := "DEGRADED"
		if pipelineHealthy && storeHealthy {
			status = "HEALTHY"
		}

		return telemetry.Summary{
			AgentID:              agentID,
			Hostname:             systemEnv.Hostname,
			OS:                   systemEnv.OS,
			OSVersion:            systemEnv.OSVersion,
			Kernel:               systemEnv.Kernel,
			Architecture:         systemEnv.Architecture,
			CPUCount:             systemEnv.CPUCount,
			Version:              version.String(),
			Status:               status,
			UptimeSeconds:        int64(time.Since(startTime).Seconds()),
			EventsIngested:       eventsIngested,
			EventsDropped:        eventsDropped,
			MemoryBytes:          m.Alloc,
			PipelineHealthy:      pipelineHealthy,
			StoreHealthy:         storeHealthy,
			AttachmentMode:       bpfLoader.ModeName(),
			AppliedPolicyVersion: int(appliedPolicyVersion.Load()),
			TimestampUnixSec:     time.Now().Unix(),
		}
	}

	var mgmtServer *mgmt.Server
	haHeartbeat := parsePositiveDurationOrDefault(cfg.ControlPlane.Heartbeat, controlplaneha.DefaultHeartbeatInterval)
	haElectionTimeout := parsePositiveDurationOrDefault(cfg.ControlPlane.ElectionTimeout, controlplaneha.DefaultElectionTimeout)
	haStateBackend := strings.TrimSpace(cfg.ControlPlane.StateBackend)
	if haStateBackend == "" {
		haStateBackend = filepath.Join(cfg.Output.Dir, "control-plane-ha.json")
	}
	haCoordinator := controlplaneha.New(controlplaneha.Config{
		Mode:              cfg.ControlPlane.Mode,
		NodeID:            firstNonEmpty(strings.TrimSpace(cfg.ControlPlane.NodeID), agentID),
		ConfiguredRole:    cfg.ControlPlane.Role,
		ConfiguredLeader:  cfg.ControlPlane.LeaderID,
		Peers:             cfg.ControlPlane.Peers,
		StateBackend:      haStateBackend,
		Address:           cfg.API.REST,
		Version:           version.String(),
		HeartbeatInterval: haHeartbeat,
		ElectionTimeout:   haElectionTimeout,
		Healthy: func() bool {
			return pipelineHealthy && storeHealthy
		},
	})
	haCtx, stopHA := context.WithCancel(context.Background())
	defer stopHA()
	go haCoordinator.Start(haCtx)
	apiServer.SetHAStatusFunc(func() api.HAStatus {
		haStatus := haCoordinator.Status()
		status := api.HAStatus{
			UpdatedAt:     haStatus.UpdatedAt.UTC().Format(time.RFC3339),
			Mode:          haStatus.Mode,
			NodeID:        haStatus.NodeID,
			Role:          haStatus.Role,
			LeaderID:      haStatus.LeaderID,
			Healthy:       haStatus.Healthy,
			PeerCount:     haStatus.PeerCount,
			Peers:         haStatus.Peers,
			StateBackend:  haStatus.StateBackend,
			FailoverReady: haStatus.FailoverReady,
			Message:       haStatus.Message,
		}
		if !haStatus.LastCheckpoint.IsZero() {
			status.LastCheckpoint = haStatus.LastCheckpoint.UTC().Format(time.RFC3339)
		}
		if mgmtServer != nil {
			status.Message = fmt.Sprintf("%s; grpc=%s rest=%s agents=%d", status.Message, cfg.API.GRPC, cfg.API.REST, len(mgmtServer.TelemetryOverview()))
		}
		return status
	})

	telemetryReporter := telemetry.NewReporter(telemetry.ReporterConfig{
		Endpoint:   cfg.Telemetry.Endpoint,
		Interval:   telemetryInterval,
		EnableTLS:  cfg.Telemetry.EnableTLS,
		CertFile:   cfg.Telemetry.CertFile,
		KeyFile:    cfg.Telemetry.KeyFile,
		CAFile:     cfg.Telemetry.CAFile,
		ServerName: cfg.Telemetry.ServerName,
		OnAck: func(status telemetry.ReporterStatus) {
			if status.DesiredPolicyVersion > 0 {
				version := int64(status.DesiredPolicyVersion)
				if appliedPolicyVersion.Load() == version {
					return
				}
				applied, err := fetchAndApplyPolicyBundle(context.Background(), policyClientCfg, status.DesiredPolicyVersion, apt, bpfLoader.Ctrl)
				if err != nil {
					logx.System().Warn("apply remote policy bundle failed", "version", status.DesiredPolicyVersion, "error", err)
					return
				}
				appliedPolicyVersion.Store(version)
				if err := saveAppliedPolicyVersion(appliedPolicyStatePath, status.DesiredPolicyVersion, status.LastAckMessage, applied.SHA256, applied.Path); err != nil {
					logx.System().Warn("save applied policy state failed", "error", err)
				}
				logx.System().Info("remote policy bundle applied", "version", status.DesiredPolicyVersion, "sha256", applied.SHA256)
			}
		},
	}, buildTelemetrySummary)
	if err := telemetryReporter.Start(context.Background()); err != nil {
		logx.System().Warn("telemetry reporter start failed", "error", err)
	}
	defer telemetryReporter.Stop()

	apiServer.SetHealthFunc(func() api.HealthStatus {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		reporterStatus := telemetryReporter.Status()
		controlStats := map[string]interface{}{}
		if bpfLoader != nil && bpfLoader.Ctrl != nil {
			controlStats = bpfLoader.Ctrl.Stats()
		}
		pidWhitelistEntries, _ := controlStats["pid_whitelist_entries"].(int)
		taintedProcesses, _ := controlStats["tainted_processes"].(int)
		activeSampleCounters, _ := controlStats["active_sample_counters"].(int)
		hs := api.HealthStatus{
			Status:               healthStatus(pipelineHealthy, storeHealthy),
			UptimeSeconds:        int64(time.Since(startTime).Seconds()),
			EbpfCollector:        bpfLoader.RB != nil,
			AttachmentMode:       bpfLoader.ModeName(),
			PipelineHealthy:      pipelineHealthy,
			StoreHealthy:         storeHealthy,
			EventsIngested:       eventsIngested,
			EventsDropped:        eventsDropped,
			MemoryBytes:          m.Alloc,
			Version:              version.String(),
			PIDWhitelistEntries:  pidWhitelistEntries,
			TaintedProcesses:     taintedProcesses,
			ActiveSampleCounters: activeSampleCounters,
			TelemetryEnabled:     reporterStatus.Enabled,
			TelemetryHealthy:     !reporterStatus.Enabled || reporterStatus.ConsecutiveFailures == 0,
			TelemetryLastError:   reporterStatus.LastError,
			TelemetryLastAck:     reporterStatus.LastAckMessage,
			DesiredPolicyVersion: reporterStatus.DesiredPolicyVersion,
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
				AgentID:              local.AgentID,
				Hostname:             local.Hostname,
				OS:                   local.OS,
				OSVersion:            local.OSVersion,
				Kernel:               local.Kernel,
				Architecture:         local.Architecture,
				CPUCount:             local.CPUCount,
				Status:               local.Status,
				Version:              local.Version,
				LastReportAt:         time.Now().UTC().Format(time.RFC3339),
				EventsIngested:       local.EventsIngested,
				EventsDropped:        local.EventsDropped,
				MemoryBytes:          local.MemoryBytes,
				UptimeSeconds:        local.UptimeSeconds,
				PipelineHealthy:      local.PipelineHealthy,
				StoreHealthy:         local.StoreHealthy,
				AttachmentMode:       local.AttachmentMode,
				AppliedPolicyVersion: local.AppliedPolicyVersion,
				EnrollmentStatus:     "approved",
			},
		}
		if mgmtServer != nil {
			for _, agent := range mgmtServer.TelemetryOverview() {
				agentsByID[agent.AgentID] = api.ClusterAgent{
					AgentID:              agent.AgentID,
					Hostname:             agent.Hostname,
					OS:                   agent.OS,
					OSVersion:            agent.OSVersion,
					Kernel:               agent.Kernel,
					Architecture:         agent.Architecture,
					CPUCount:             agent.CPUCount,
					Group:                agent.Group,
					Tags:                 agent.Tags,
					Status:               agent.Status,
					StatusReason:         agent.StatusReason,
					Version:              agent.Version,
					LastReportAt:         agent.LastReportAt.UTC().Format(time.RFC3339),
					LastReportAge:        agent.LastReportAge,
					EventsIngested:       agent.EventsIngested,
					EventsDropped:        agent.EventsDropped,
					MemoryBytes:          agent.MemoryBytes,
					UptimeSeconds:        agent.UptimeSeconds,
					PipelineHealthy:      agent.PipelineHealthy,
					StoreHealthy:         agent.StoreHealthy,
					AttachmentMode:       agent.AttachmentMode,
					AppliedPolicyVersion: agent.AppliedPolicyVersion,
					EnrollmentStatus:     agent.EnrollmentStatus,
					EnrollmentNote:       agent.EnrollmentNote,
					EnrollmentUpdatedAt:  formatTimePtr(agent.EnrollmentUpdatedAt),
					CertFingerprint:      agent.CertFingerprint,
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
			AgentID:              local.AgentID,
			Hostname:             local.Hostname,
			OS:                   local.OS,
			OSVersion:            local.OSVersion,
			Kernel:               local.Kernel,
			Architecture:         local.Architecture,
			CPUCount:             local.CPUCount,
			Status:               local.Status,
			Version:              local.Version,
			LastReportAt:         time.Now().UTC().Format(time.RFC3339),
			EventsIngested:       local.EventsIngested,
			EventsDropped:        local.EventsDropped,
			MemoryBytes:          local.MemoryBytes,
			UptimeSeconds:        local.UptimeSeconds,
			PipelineHealthy:      local.PipelineHealthy,
			StoreHealthy:         local.StoreHealthy,
			AttachmentMode:       local.AttachmentMode,
			AppliedPolicyVersion: local.AppliedPolicyVersion,
			EnrollmentStatus:     "approved",
		}
		includeLocal := group == "" && tag == ""
		if includeLocal {
			fleet.Agents = append(fleet.Agents, localAgent)
		}
		if mgmtServer != nil {
			for _, agent := range mgmtServer.FleetSnapshot(mgmt.FleetFilter{Group: group, Tag: tag}) {
				fleet.Agents = append(fleet.Agents, api.ClusterAgent{
					AgentID:              agent.AgentID,
					Hostname:             agent.Hostname,
					OS:                   agent.OS,
					OSVersion:            agent.OSVersion,
					Kernel:               agent.Kernel,
					Architecture:         agent.Architecture,
					CPUCount:             agent.CPUCount,
					Group:                agent.Group,
					Tags:                 agent.Tags,
					Status:               agent.Status,
					StatusReason:         agent.StatusReason,
					Version:              agent.Version,
					LastReportAt:         agent.LastReportAt.UTC().Format(time.RFC3339),
					LastReportAge:        agent.LastReportAge,
					EventsIngested:       agent.EventsIngested,
					EventsDropped:        agent.EventsDropped,
					MemoryBytes:          agent.MemoryBytes,
					UptimeSeconds:        agent.UptimeSeconds,
					PipelineHealthy:      agent.PipelineHealthy,
					StoreHealthy:         agent.StoreHealthy,
					AttachmentMode:       agent.AttachmentMode,
					AppliedPolicyVersion: agent.AppliedPolicyVersion,
					EnrollmentStatus:     agent.EnrollmentStatus,
					EnrollmentNote:       agent.EnrollmentNote,
					EnrollmentUpdatedAt:  formatTimePtr(agent.EnrollmentUpdatedAt),
					CertFingerprint:      agent.CertFingerprint,
				})
			}
		}
		return fleet
	})
	apiServer.SetFleetUpdateFunc(func(update api.FleetUpdate) error {
		if mgmtServer == nil {
			err := fmt.Errorf("mgmt server not available")
			fleetAudit.record("fleet_update", update.Actor, update.Role, update.AgentID, update.Note, "failed", err.Error())
			logControlAudit(auditStore, "fleet", "fleet_update", update.Actor, update.Role, update.AgentID, update.Note, "failed", err.Error())
			return err
		}
		action := strings.ToLower(strings.TrimSpace(update.Action))
		if action == "" {
			action = "metadata"
		}
		if action == "approve" || action == "approved" || action == "quarantine" || action == "quarantined" || action == "revoke" || action == "revoked" {
			status := update.Status
			if status == "" {
				status = action
			}
			if err := mgmtServer.SetAgentEnrollment(update.AgentID, status, update.Note); err != nil {
				fleetAudit.record("fleet_"+action, update.Actor, update.Role, update.AgentID, update.Note, "failed", err.Error())
				logControlAudit(auditStore, "fleet", "fleet_"+action, update.Actor, update.Role, update.AgentID, update.Note, "failed", err.Error())
				return err
			}
			message := fmt.Sprintf("agent enrollment status updated: %s", status)
			fleetAudit.record("fleet_"+action, update.Actor, update.Role, update.AgentID, update.Note, "updated", message)
			logControlAudit(auditStore, "fleet", "fleet_"+action, update.Actor, update.Role, update.AgentID, update.Note, "updated", message)
			return nil
		}
		mgmtServer.UpsertAgentMetadata(update.AgentID, update.Group, update.Tags)
		message := fmt.Sprintf("fleet metadata updated: group=%s tags=%s", strings.TrimSpace(update.Group), strings.Join(update.Tags, ","))
		fleetAudit.record(
			"fleet_update",
			update.Actor,
			update.Role,
			update.AgentID,
			update.Note,
			"updated",
			message,
		)
		logControlAudit(auditStore, "fleet", "fleet_update", update.Actor, update.Role, update.AgentID, update.Note, "updated", message)
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
	apiServer.SetBackupFunc(func() api.BackupSummary {
		summary := backupSummaryState.snapshot()
		summary.History = backupAudit.snapshot()
		return summary
	})
	apiServer.SetBackupDownloadFunc(func(actor, role string) (api.BackupDownload, error) {
		summary := backupSummaryState.snapshot()
		if strings.TrimSpace(summary.LastBackupPath) == "" {
			return api.BackupDownload{}, fmt.Errorf("backup archive not available")
		}
		backupAudit.record("backup_download", actor, role, summary.LastBackupPath, "", "downloaded", "backup archive downloaded")
		logControlAudit(auditStore, "backup", "backup_download", actor, role, summary.LastBackupPath, "", "downloaded", "backup archive downloaded")
		return api.BackupDownload{
			Path:     summary.LastBackupPath,
			FileName: filepath.Base(summary.LastBackupPath),
		}, nil
	})
	runBackupAction := func(req api.BackupActionRequest) (api.BackupActionResult, error) {
		action := strings.ToLower(strings.TrimSpace(req.Action))
		if action == "" {
			action = "create"
		}
		performedAt := time.Now().UTC().Format(time.RFC3339)
		backupRoot := filepath.Join(cfg.Output.Dir, "backups")
		restoreRoot := filepath.Join(cfg.Output.Dir, "restore-staging")

		switch action {
		case "create", "backup":
			if err := os.MkdirAll(backupRoot, 0700); err != nil {
				backupAudit.record("backup_create", req.Actor, req.Role, backupRoot, req.Note, "failed", err.Error())
				logControlAudit(auditStore, "backup", "backup_create", req.Actor, req.Role, backupRoot, req.Note, "failed", err.Error())
				return api.BackupActionResult{Status: "failed", Action: action, Message: err.Error(), PerformedAt: performedAt}, err
			}
			backupPath := strings.TrimSpace(req.BackupPath)
			if backupPath == "" {
				backupPath = filepath.Join(backupRoot, "providapt-backup-"+time.Now().UTC().Format("20060102T150405Z")+".tar.gz")
			}
			if !pathWithin(cfg.Output.Dir, backupPath) {
				err := fmt.Errorf("backup_path must stay within output dir")
				backupAudit.record("backup_create", req.Actor, req.Role, backupPath, req.Note, "failed", err.Error())
				logControlAudit(auditStore, "backup", "backup_create", req.Actor, req.Role, backupPath, req.Note, "failed", err.Error())
				return api.BackupActionResult{Status: "failed", Action: action, BackupPath: backupPath, Message: err.Error(), PerformedAt: performedAt}, err
			}
			meta, err := pipe.CreateCheckpointBackup(backupPath)
			if err != nil {
				backupAudit.record("backup_create", req.Actor, req.Role, backupPath, req.Note, "failed", err.Error())
				backupSummaryState.update(api.BackupSummary{
					LastBackupPath: backupPath,
					LastAction:     action,
					LastActor:      req.Actor,
					LastRole:       req.Role,
					LastStatus:     "failed",
					LastMessage:    err.Error(),
					LastBackupAt:   performedAt,
					History:        backupAudit.snapshot(),
				})
				logControlAudit(auditStore, "backup", "backup_create", req.Actor, req.Role, backupPath, req.Note, "failed", err.Error())
				return api.BackupActionResult{Status: "failed", Action: action, BackupPath: backupPath, Message: err.Error(), PerformedAt: performedAt}, err
			}
			message := "checkpoint backup created"
			backupAudit.record("backup_create", req.Actor, req.Role, meta.Path, req.Note, "created", message)
			backupSummaryState.update(api.BackupSummary{
				LastBackupPath: meta.Path,
				LastAction:     action,
				LastActor:      req.Actor,
				LastRole:       req.Role,
				LastStatus:     "created",
				LastMessage:    message,
				LastBackupAt:   performedAt,
				SizeBytes:      meta.SizeBytes,
				DownloadURL:    "/api/v1/control/backup/download",
				History:        backupAudit.snapshot(),
			})
			logControlAudit(auditStore, "backup", "backup_create", req.Actor, req.Role, meta.Path, req.Note, "created", message)
			return api.BackupActionResult{
				Status:      "created",
				Message:     message,
				Action:      action,
				BackupPath:  meta.Path,
				DownloadURL: "/api/v1/control/backup/download",
				SizeBytes:   meta.SizeBytes,
				PerformedAt: performedAt,
			}, nil
		case "restore", "restore_staging", "validate_restore":
			backupPath := strings.TrimSpace(req.BackupPath)
			if backupPath == "" {
				backupPath = backupSummaryState.snapshot().LastBackupPath
			}
			if backupPath == "" {
				err := fmt.Errorf("backup_path is required for restore staging")
				backupAudit.record("backup_restore_staging", req.Actor, req.Role, "", req.Note, "failed", err.Error())
				logControlAudit(auditStore, "backup", "backup_restore_staging", req.Actor, req.Role, "", req.Note, "failed", err.Error())
				return api.BackupActionResult{Status: "failed", Action: action, Message: err.Error(), PerformedAt: performedAt}, err
			}
			targetDir := strings.TrimSpace(req.TargetDir)
			if targetDir == "" {
				targetDir = filepath.Join(restoreRoot, "restore-"+time.Now().UTC().Format("20060102T150405Z"))
			}
			if !pathWithin(cfg.Output.Dir, targetDir) {
				err := fmt.Errorf("target_dir must stay within output dir")
				backupAudit.record("backup_restore_staging", req.Actor, req.Role, backupPath, req.Note, "failed", err.Error())
				logControlAudit(auditStore, "backup", "backup_restore_staging", req.Actor, req.Role, backupPath, req.Note, "failed", err.Error())
				return api.BackupActionResult{Status: "failed", Action: action, BackupPath: backupPath, RestorePath: targetDir, Message: err.Error(), PerformedAt: performedAt}, err
			}
			if err := backup.RestoreCheckpoint(backupPath, targetDir); err != nil {
				backupAudit.record("backup_restore_staging", req.Actor, req.Role, backupPath, req.Note, "failed", err.Error())
				logControlAudit(auditStore, "backup", "backup_restore_staging", req.Actor, req.Role, backupPath, req.Note, "failed", err.Error())
				return api.BackupActionResult{Status: "failed", Action: action, BackupPath: backupPath, RestorePath: targetDir, Message: err.Error(), PerformedAt: performedAt}, err
			}
			message := "backup restored to staging directory"
			current := backupSummaryState.snapshot()
			current.LastRestorePath = targetDir
			current.LastAction = action
			current.LastActor = req.Actor
			current.LastRole = req.Role
			current.LastStatus = "restored_staging"
			current.LastMessage = message
			current.LastRestoreAt = performedAt
			backupAudit.record("backup_restore_staging", req.Actor, req.Role, backupPath, req.Note, "restored_staging", message)
			current.History = backupAudit.snapshot()
			backupSummaryState.update(current)
			logControlAudit(auditStore, "backup", "backup_restore_staging", req.Actor, req.Role, backupPath, req.Note, "restored_staging", message)
			return api.BackupActionResult{
				Status:      "restored_staging",
				Message:     message,
				Action:      action,
				BackupPath:  backupPath,
				RestorePath: targetDir,
				PerformedAt: performedAt,
			}, nil
		case "prepare_cutover", "restore_cutover_plan":
			current := backupSummaryState.snapshot()
			if approvalRequired(cfg, "backup.prepare_cutover") && !approvalBook.consumeApproved("backup.prepare_cutover", req.Actor) {
				err := fmt.Errorf("backup.prepare_cutover requires approval")
				backupAudit.record("backup_prepare_cutover", req.Actor, req.Role, "", req.Note, "failed", err.Error())
				logControlAudit(auditStore, "backup", "backup_prepare_cutover", req.Actor, req.Role, "", req.Note, "failed", err.Error())
				return api.BackupActionResult{Status: "failed", Action: action, Message: err.Error(), PerformedAt: performedAt}, err
			}
			if strings.TrimSpace(current.LastRestorePath) == "" {
				err := fmt.Errorf("restore staging path is required before preparing cutover")
				backupAudit.record("backup_prepare_cutover", req.Actor, req.Role, "", req.Note, "failed", err.Error())
				logControlAudit(auditStore, "backup", "backup_prepare_cutover", req.Actor, req.Role, "", req.Note, "failed", err.Error())
				return api.BackupActionResult{Status: "failed", Action: action, Message: err.Error(), PerformedAt: performedAt}, err
			}
			planPath, err := writeRestoreCutoverPlan(cfg.Output.Dir, current.LastRestorePath)
			if err != nil {
				backupAudit.record("backup_prepare_cutover", req.Actor, req.Role, current.LastRestorePath, req.Note, "failed", err.Error())
				logControlAudit(auditStore, "backup", "backup_prepare_cutover", req.Actor, req.Role, current.LastRestorePath, req.Note, "failed", err.Error())
				return api.BackupActionResult{Status: "failed", Action: action, RestorePath: current.LastRestorePath, Message: err.Error(), PerformedAt: performedAt}, err
			}
			message := "restore cutover plan generated; stop ProvidAPT before executing"
			current.LastAction = action
			current.LastActor = req.Actor
			current.LastRole = req.Role
			current.LastStatus = "cutover_ready"
			current.LastMessage = message + ": " + planPath
			backupAudit.record("backup_prepare_cutover", req.Actor, req.Role, planPath, req.Note, "cutover_ready", message)
			current.History = backupAudit.snapshot()
			backupSummaryState.update(current)
			logControlAudit(auditStore, "backup", "backup_prepare_cutover", req.Actor, req.Role, planPath, req.Note, "cutover_ready", message)
			return api.BackupActionResult{
				Status:      "cutover_ready",
				Message:     current.LastMessage,
				Action:      action,
				BackupPath:  current.LastBackupPath,
				RestorePath: current.LastRestorePath,
				PerformedAt: performedAt,
			}, nil
		default:
			return api.BackupActionResult{Status: "failed", Action: action, Message: "unsupported backup action", PerformedAt: performedAt}, fmt.Errorf("unsupported backup action %q", action)
		}
	}
	apiServer.SetBackupActionFunc(runBackupAction)
	backupSchedulerStop := startBackupScheduler(cfg, runBackupAction)
	defer backupSchedulerStop()
	apiServer.SetSecurityStatusFunc(func() api.SecurityStatus {
		summary := securitySummaryState.snapshot()
		summary.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		summary.CertFile = cfg.TLS.CertFile
		summary.KeyFile = cfg.TLS.KeyFile
		summary.CAFile = cfg.TLS.CAFile
		if strings.TrimSpace(cfg.TLS.CertFile) != "" {
			needed, err := certauth.NeedsRotation(cfg.TLS.CertFile, 30*24*time.Hour)
			summary.RotationNeeded = needed
			if err != nil && summary.LastMessage == "" {
				summary.LastStatus = "check_failed"
				summary.LastMessage = err.Error()
			}
		}
		summary.History = securityAudit.snapshot()
		return summary
	})
	apiServer.SetSecurityActionFunc(func(req api.SecurityActionRequest) (api.SecurityActionResult, error) {
		action := strings.ToLower(strings.TrimSpace(req.Action))
		if action == "" {
			action = "check_rotation"
		}
		performedAt := time.Now().UTC().Format(time.RFC3339)
		switch action {
		case "check_rotation":
			status := securitySummaryState.snapshot()
			status.UpdatedAt = performedAt
			status.CertFile = cfg.TLS.CertFile
			status.KeyFile = cfg.TLS.KeyFile
			status.CAFile = cfg.TLS.CAFile
			needed, err := certauth.NeedsRotation(cfg.TLS.CertFile, 30*24*time.Hour)
			status.RotationNeeded = needed
			status.LastStatus = "checked"
			status.LastMessage = "certificate rotation checked"
			if err != nil {
				status.LastStatus = "check_failed"
				status.LastMessage = err.Error()
			}
			securityAudit.record("security_check_rotation", req.Actor, req.Role, cfg.TLS.CertFile, req.Note, status.LastStatus, status.LastMessage)
			status.History = securityAudit.snapshot()
			securitySummaryState.update(status)
			logControlAudit(auditStore, "security", "security_check_rotation", req.Actor, req.Role, cfg.TLS.CertFile, req.Note, status.LastStatus, status.LastMessage)
			if err != nil {
				return api.SecurityActionResult{Status: status.LastStatus, Message: status.LastMessage, Action: action, CertFile: cfg.TLS.CertFile, PerformedAt: performedAt}, err
			}
			return api.SecurityActionResult{Status: status.LastStatus, Message: status.LastMessage, Action: action, CertFile: cfg.TLS.CertFile, PerformedAt: performedAt}, nil
		case "rotate_server_cert":
			if strings.TrimSpace(cfg.TLS.CertFile) == "" || strings.TrimSpace(cfg.TLS.KeyFile) == "" || strings.TrimSpace(cfg.TLS.CAFile) == "" {
				err := fmt.Errorf("tls cert_file, key_file, and ca_file are required")
				securityAudit.record("security_rotate_server_cert", req.Actor, req.Role, cfg.TLS.CertFile, req.Note, "failed", err.Error())
				logControlAudit(auditStore, "security", "security_rotate_server_cert", req.Actor, req.Role, cfg.TLS.CertFile, req.Note, "failed", err.Error())
				return api.SecurityActionResult{Status: "failed", Message: err.Error(), Action: action, PerformedAt: performedAt}, err
			}
			certCfg := &certauth.Config{
				CADir:     filepath.Dir(cfg.TLS.CAFile),
				ServerDir: filepath.Dir(cfg.TLS.CertFile),
			}
			if err := certauth.RotateServerCert(certCfg, cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
				securityAudit.record("security_rotate_server_cert", req.Actor, req.Role, cfg.TLS.CertFile, req.Note, "failed", err.Error())
				logControlAudit(auditStore, "security", "security_rotate_server_cert", req.Actor, req.Role, cfg.TLS.CertFile, req.Note, "failed", err.Error())
				return api.SecurityActionResult{Status: "failed", Message: err.Error(), Action: action, CertFile: cfg.TLS.CertFile, PerformedAt: performedAt}, err
			}
			message := "server certificate rotated; reload or restart services to use it"
			status := api.SecurityStatus{
				UpdatedAt:      performedAt,
				CertFile:       cfg.TLS.CertFile,
				KeyFile:        cfg.TLS.KeyFile,
				CAFile:         cfg.TLS.CAFile,
				RotationNeeded: false,
				LastStatus:     "rotated",
				LastMessage:    message,
				LastRotatedAt:  performedAt,
			}
			securityAudit.record("security_rotate_server_cert", req.Actor, req.Role, cfg.TLS.CertFile, req.Note, "rotated", message)
			status.History = securityAudit.snapshot()
			securitySummaryState.update(status)
			logControlAudit(auditStore, "security", "security_rotate_server_cert", req.Actor, req.Role, cfg.TLS.CertFile, req.Note, "rotated", message)
			return api.SecurityActionResult{Status: "rotated", Message: message, Action: action, CertFile: cfg.TLS.CertFile, PerformedAt: performedAt}, nil
		default:
			err := fmt.Errorf("unsupported security action %q", action)
			securityAudit.record("security_action", req.Actor, req.Role, "", req.Note, "failed", err.Error())
			logControlAudit(auditStore, "security", "security_action", req.Actor, req.Role, "", req.Note, "failed", err.Error())
			return api.SecurityActionResult{Status: "failed", Message: err.Error(), Action: action, PerformedAt: performedAt}, err
		}
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
	complianceEntries := func(limit int) []audit.Entry {
		if auditStore == nil {
			return nil
		}
		if limit <= 0 {
			limit = cfg.Compliance.MaxAuditEntries
		}
		if limit <= 0 {
			limit = 10000
		}
		entries, err := auditStore.Query("", time.Time{}, limit)
		if err != nil {
			return nil
		}
		return entries
	}
	complianceReportDir := func() string {
		if dir := strings.TrimSpace(cfg.Compliance.ReportDir); dir != "" {
			return dir
		}
		return filepath.Join(cfg.Output.Dir, "compliance")
	}
	siemOutboxPath := func() string {
		if dir := strings.TrimSpace(cfg.SIEM.OutboxDir); dir != "" {
			return filepath.Join(dir, "siem-events.ndjson")
		}
		return filepath.Join(cfg.Output.Dir, "siem-outbox", "siem-events.ndjson")
	}
	buildComplianceStatus := func() api.ComplianceStatus {
		entries := complianceEntries(cfg.Compliance.MaxAuditEntries)
		now := time.Now().UTC()
		status := complianceSummaryState.snapshot()
		status.UpdatedAt = now.Format(time.RFC3339)
		status.RetentionDays = cfg.Compliance.RetentionDays
		status.MaxAuditEntries = cfg.Compliance.MaxAuditEntries
		status.AuditEntries = len(entries)
		if cfg.Compliance.RetentionDays > 0 {
			status.OldestAllowedAt = now.Add(-time.Duration(cfg.Compliance.RetentionDays) * 24 * time.Hour).Format(time.RFC3339)
		}
		for i, entry := range entries {
			if i == 0 || entry.Timestamp.Before(parseTimeOrZero(status.AuditOldestAt)) {
				status.AuditOldestAt = entry.Timestamp.UTC().Format(time.RFC3339)
			}
			if i == 0 || entry.Timestamp.After(parseTimeOrZero(status.AuditNewestAt)) {
				status.AuditNewestAt = entry.Timestamp.UTC().Format(time.RFC3339)
			}
		}
		status.SIEM.Enabled = cfg.SIEM.Enabled
		status.SIEM.Provider = firstNonEmpty(strings.TrimSpace(cfg.SIEM.Provider), "generic")
		status.SIEM.Endpoint = strings.TrimSpace(cfg.SIEM.Endpoint)
		status.SIEM.Format = firstNonEmpty(strings.TrimSpace(cfg.SIEM.Format), "json")
		status.SIEM.MinSeverity = firstNonEmpty(strings.TrimSpace(cfg.SIEM.MinSeverity), "INFO")
		status.SIEM.OutboxPath = siemOutboxPath()
		status.Approvals = approvalBook.status(cfg.Compliance.RequireApprovals, cfg.Compliance.ApprovalActions, cfg.Compliance.ApprovalTTL)
		status.RecommendedActions = complianceRecommendations(status)
		status.ReadinessScore, status.ReadinessGrade = complianceReadiness(status)
		complianceSummaryState.update(status)
		return status
	}
	apiServer.SetComplianceStatusFunc(buildComplianceStatus)
	apiServer.SetComplianceActionFunc(func(req api.ComplianceActionRequest) (api.ComplianceActionResult, error) {
		action := strings.ToLower(strings.TrimSpace(req.Action))
		if action == "" {
			action = "status"
		}
		performedAt := time.Now().UTC().Format(time.RFC3339)
		status := buildComplianceStatus()
		result := api.ComplianceActionResult{Status: "completed", PerformedAt: performedAt}
		switch action {
		case "status":
			result.Message = "compliance status refreshed"
		case "export_audit":
			entries := complianceEntries(cfg.Compliance.MaxAuditEntries)
			path, err := exportAuditEvidence(complianceReportDir(), entries, firstNonEmpty(strings.TrimSpace(req.Format), "csv"))
			if err != nil {
				logControlAudit(auditStore, "compliance", action, req.Actor, req.Role, "", req.Note, "failed", err.Error())
				return api.ComplianceActionResult{Status: "failed", Message: err.Error(), PerformedAt: performedAt}, err
			}
			status.LastExportPath = path
			result.Path = path
			result.Message = "audit evidence exported"
		case "generate_report":
			reportFormat := strings.ToLower(strings.TrimSpace(req.Format))
			var reportPath string
			var err error
			if reportFormat == "html" {
				reportPath, err = writeComplianceHTMLReport(complianceReportDir(), status)
			} else {
				reportPath, err = writeComplianceReport(complianceReportDir(), status)
			}
			if err != nil {
				logControlAudit(auditStore, "compliance", action, req.Actor, req.Role, "", req.Note, "failed", err.Error())
				return api.ComplianceActionResult{Status: "failed", Message: err.Error(), PerformedAt: performedAt}, err
			}
			status.LastReportPath = reportPath
			result.Path = reportPath
			result.Message = "compliance report generated"
		case "test_siem":
			siemStatus, err := writeSIEMTestEvent(cfg, siemOutboxPath(), req.Actor, req.Note)
			status.SIEM = siemStatus
			result.SIEM = &siemStatus
			if err != nil {
				logControlAudit(auditStore, "compliance", action, req.Actor, req.Role, "", req.Note, "failed", err.Error())
				return api.ComplianceActionResult{Status: "failed", Message: err.Error(), SIEM: &siemStatus, PerformedAt: performedAt}, err
			}
			result.Message = "SIEM test event queued"
		case "apply_retention":
			retention, err := applyAuditRetention(auditStore, cfg, complianceSummaryState)
			if err != nil {
				logControlAudit(auditStore, "compliance", action, req.Actor, req.Role, "", req.Note, "failed", err.Error())
				return api.ComplianceActionResult{Status: "failed", Message: err.Error(), PerformedAt: performedAt}, err
			}
			status = complianceSummaryState.snapshot()
			result.Path = retention.ArchivePath
			result.Message = fmt.Sprintf("audit retention applied; archived %d entrie(s)", retention.Archived)
		case "request_approval":
			approval := approvalBook.request(req.Target, "", req.Actor, req.Note, approvalTTL(cfg))
			status.Approvals = approvalBook.status(cfg.Compliance.RequireApprovals, cfg.Compliance.ApprovalActions, cfg.Compliance.ApprovalTTL)
			result.Approval = &approval
			result.Message = "approval requested"
		case "approve":
			approval, ok := approvalBook.resolve(req.ApprovalID, "approved", req.Actor, req.Note)
			if !ok {
				err := fmt.Errorf("approval_id not found")
				return api.ComplianceActionResult{Status: "failed", Message: err.Error(), PerformedAt: performedAt}, err
			}
			status.Approvals = approvalBook.status(cfg.Compliance.RequireApprovals, cfg.Compliance.ApprovalActions, cfg.Compliance.ApprovalTTL)
			result.Approval = &approval
			result.Message = "approval granted"
		case "reject":
			approval, ok := approvalBook.resolve(req.ApprovalID, "rejected", req.Actor, req.Note)
			if !ok {
				err := fmt.Errorf("approval_id not found")
				return api.ComplianceActionResult{Status: "failed", Message: err.Error(), PerformedAt: performedAt}, err
			}
			status.Approvals = approvalBook.status(cfg.Compliance.RequireApprovals, cfg.Compliance.ApprovalActions, cfg.Compliance.ApprovalTTL)
			result.Approval = &approval
			result.Message = "approval rejected"
		default:
			err := fmt.Errorf("unsupported compliance action: %s", req.Action)
			logControlAudit(auditStore, "compliance", action, req.Actor, req.Role, "", req.Note, "failed", err.Error())
			return api.ComplianceActionResult{Status: "failed", Message: err.Error(), PerformedAt: performedAt}, err
		}
		status.LastActionStatus = result.Status
		status.LastActionMessage = result.Message
		complianceSummaryState.update(status)
		logControlAudit(auditStore, "compliance", action, req.Actor, req.Role, result.Path, req.Note, result.Status, result.Message)
		return result, nil
	})
	siemForwarderStop := startSIEMForwarder(cfg, siemOutboxPath(), complianceSummaryState)
	defer siemForwarderStop()
	auditRetentionStop := startAuditRetentionScheduler(cfg, auditStore, complianceSummaryState)
	defer auditRetentionStop()
	complianceReportStop := startComplianceReportScheduler(cfg, complianceReportDir, buildComplianceStatus, complianceSummaryState)
	defer complianceReportStop()
	reportingAgentCount := func() int {
		agents := map[string]struct{}{}
		local := buildTelemetrySummary()
		if strings.TrimSpace(local.AgentID) != "" {
			agents[local.AgentID] = struct{}{}
		}
		if mgmtServer != nil {
			for _, agent := range mgmtServer.FleetSnapshot(mgmt.FleetFilter{}) {
				if strings.TrimSpace(agent.AgentID) != "" {
					agents[agent.AgentID] = struct{}{}
				}
			}
		}
		return len(agents)
	}
	inspectLicense := func() api.LicenseStatus {
		summary := api.LicenseStatus{
			UpdatedAt:          time.Now().UTC().Format(time.RFC3339),
			Path:               strings.TrimSpace(cfg.License.Path),
			CurrentVersion:     version.String(),
			MachineFingerprint: machineFingerprint(),
			History:            licenseAudit.snapshot(),
			GracePeriodDays:    cfg.License.GracePeriodDays,
			MaxAgents:          cfg.License.MaxAgents,
			ReportingAgents:    reportingAgentCount(),
			SignaturePresent:   false,
			SignatureVerified:  false,
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
		if doc.MaxAgents > 0 {
			summary.MaxAgents = doc.MaxAgents
		}
		if summary.MaxAgents > 0 {
			summary.SeatsAvailable = summary.MaxAgents - summary.ReportingAgents
			if summary.SeatsAvailable < 0 {
				summary.SeatLimitExceeded = true
				if summary.LastError == "" {
					summary.LastError = "license agent seat limit exceeded"
				}
			}
		}
		summary.BoundFingerprint = strings.TrimSpace(doc.MachineFingerprint)
		summary.BindingVerified = summary.BoundFingerprint == "" || strings.EqualFold(summary.BoundFingerprint, summary.MachineFingerprint)
		if !summary.BindingVerified {
			summary.LastError = "license machine fingerprint mismatch"
		}
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
		if action == "import" || action == "renew" || action == "activate_offline" {
			targetPath := strings.TrimSpace(req.LicensePath)
			if targetPath == "" {
				targetPath = strings.TrimSpace(cfg.License.Path)
			}
			if targetPath == "" {
				targetPath = filepath.Join(cfg.Output.Dir, "license.lic")
				cfg.License.Path = targetPath
			}
			if !pathWithin(cfg.Output.Dir, targetPath) && !pathWithin("/etc/providapt", targetPath) {
				err := fmt.Errorf("license_path must stay within output dir or /etc/providapt")
				licenseAudit.record("license_import", req.Actor, req.Role, targetPath, req.Note, "failed", err.Error())
				return api.LicenseActionResult{Status: "failed", Message: err.Error(), ValidatedAt: time.Now().UTC().Format(time.RFC3339)}, err
			}
			data := strings.TrimSpace(req.LicenseData)
			if data == "" {
				err := fmt.Errorf("license_data is required")
				licenseAudit.record("license_import", req.Actor, req.Role, targetPath, req.Note, "failed", err.Error())
				return api.LicenseActionResult{Status: "failed", Message: err.Error(), ValidatedAt: time.Now().UTC().Format(time.RFC3339)}, err
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
				licenseAudit.record("license_import", req.Actor, req.Role, targetPath, req.Note, "failed", err.Error())
				return api.LicenseActionResult{Status: "failed", Message: err.Error(), ValidatedAt: time.Now().UTC().Format(time.RFC3339)}, err
			}
			if err := os.WriteFile(targetPath, []byte(data+"\n"), 0640); err != nil {
				licenseAudit.record("license_import", req.Actor, req.Role, targetPath, req.Note, "failed", err.Error())
				return api.LicenseActionResult{Status: "failed", Message: err.Error(), ValidatedAt: time.Now().UTC().Format(time.RFC3339)}, err
			}
			cfg.License.Path = targetPath
			licenseAudit.record("license_import", req.Actor, req.Role, targetPath, req.Note, "imported", "offline license imported")
			logControlAudit(auditStore, "license", "license_import", req.Actor, req.Role, targetPath, req.Note, "imported", "offline license imported")
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
		if summary.Present && summary.BindingVerified && !summary.SeatLimitExceeded && !summary.Revoked && (!summary.Expired || summary.InGracePeriod) && (summary.SignaturePresent == false || summary.SignatureVerified) && (summary.LastError == "" || summary.InGracePeriod) {
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
						"path":                summary.Path,
						"actor":               req.Actor,
						"role":                req.Role,
						"note":                req.Note,
						"size_bytes":          summary.SizeBytes,
						"license_id":          summary.LicenseID,
						"machine_fingerprint": summary.MachineFingerprint,
						"grace":               summary.InGracePeriod,
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
			BindingVerified:   summary.BindingVerified,
		}
		if summary.InGracePeriod {
			result.Message = "license validated within grace period"
		}
		if !summary.Present || !summary.BindingVerified || summary.SeatLimitExceeded || summary.Revoked || (summary.Expired && !summary.InGracePeriod) || (summary.SignaturePresent && !summary.SignatureVerified) || (summary.LastError != "" && !summary.InGracePeriod) {
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
		summary.ApplyCommand = firstNonEmpty(strings.TrimSpace(cached.ApplyCommand), strings.TrimSpace(cfg.Upgrade.ApplyCommand))
		summary.RollbackCommand = firstNonEmpty(strings.TrimSpace(cached.RollbackCommand), strings.TrimSpace(cfg.Upgrade.RollbackCommand))
		summary.CanaryPercent = cfg.Upgrade.CanaryPercent
		summary.LastAction = cached.LastAction
		summary.LastActor = cached.LastActor
		summary.LastActionAt = cached.LastActionAt
		summary.LastNote = cached.LastNote
		summary.LastVerifiedAt = cached.LastVerifiedAt
		summary.AppliedAt = cached.AppliedAt
		summary.RolledBackAt = cached.RolledBackAt
		summary.History = upgradeAudit.snapshot()
		upgradeSummaryState.update(summary)
		return summary
	})
	apiServer.SetUpgradeActionFunc(func(req api.UpgradeActionRequest) (api.UpgradeActionResult, error) {
		action := strings.ToLower(strings.TrimSpace(req.Action))
		if action == "" {
			action = "check"
		}
		if action != "check" && action != "record" && action != "preflight" && action != "download" && action != "apply" && action != "rollback" {
			err := fmt.Errorf("unsupported upgrade action: %s", req.Action)
			upgradeAudit.record("upgrade_action", req.Actor, req.Role, version.String(), req.Note, "failed", err.Error())
			return api.UpgradeActionResult{
				Status:      "failed",
				Message:     err.Error(),
				PerformedAt: time.Now().UTC().Format(time.RFC3339),
			}, err
		}
		if action == "preflight" && approvalRequired(cfg, "upgrade.preflight") && !approvalBook.consumeApproved("upgrade.preflight", req.Actor) {
			err := fmt.Errorf("upgrade.preflight requires approval")
			upgradeAudit.record("upgrade_"+action, req.Actor, req.Role, version.String(), req.Note, "failed", err.Error())
			return api.UpgradeActionResult{Status: "failed", Message: err.Error(), PerformedAt: time.Now().UTC().Format(time.RFC3339)}, err
		}
		if action == "apply" && approvalRequired(cfg, "upgrade.apply") && !approvalBook.consumeApproved("upgrade.apply", req.Actor) {
			err := fmt.Errorf("upgrade.apply requires approval")
			upgradeAudit.record("upgrade_"+action, req.Actor, req.Role, version.String(), req.Note, "failed", err.Error())
			return api.UpgradeActionResult{Status: "failed", Message: err.Error(), PerformedAt: time.Now().UTC().Format(time.RFC3339)}, err
		}
		if action == "rollback" && approvalRequired(cfg, "upgrade.rollback") && !approvalBook.consumeApproved("upgrade.rollback", req.Actor) {
			err := fmt.Errorf("upgrade.rollback requires approval")
			upgradeAudit.record("upgrade_"+action, req.Actor, req.Role, version.String(), req.Note, "failed", err.Error())
			return api.UpgradeActionResult{Status: "failed", Message: err.Error(), PerformedAt: time.Now().UTC().Format(time.RFC3339)}, err
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
		if action == "download" || action == "preflight" || action == "apply" {
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
		summary.AppliedAt = cached.AppliedAt
		summary.RolledBackAt = cached.RolledBackAt
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
		} else if action == "apply" {
			summary.LastVerifiedAt = performedAt
			if !summary.PreflightReady {
				status = "failed"
				if summary.LastError != "" {
					message = summary.LastError
				} else if !summary.RollbackReady {
					message = "rollback plan not configured"
				} else {
					message = "upgrade preflight failed"
				}
			} else if strings.TrimSpace(cfg.Upgrade.ApplyCommand) == "" {
				status = "failed"
				message = "upgrade.apply_command not configured"
			} else if output, err := runUpgradeCommand(cfg.Upgrade.ApplyCommand, packagePath, rollbackPlan); err != nil {
				status = "failed"
				message = strings.TrimSpace(output)
				if message == "" {
					message = err.Error()
				}
			} else {
				status = "applied"
				summary.AppliedAt = performedAt
				message = firstNonEmpty(strings.TrimSpace(output), "upgrade applied")
			}
		} else if action == "rollback" {
			if strings.TrimSpace(cfg.Upgrade.RollbackCommand) == "" {
				status = "failed"
				message = "upgrade.rollback_command not configured"
			} else if output, err := runUpgradeCommand(cfg.Upgrade.RollbackCommand, packagePath, rollbackPlan); err != nil {
				status = "failed"
				message = strings.TrimSpace(output)
				if message == "" {
					message = err.Error()
				}
			} else {
				status = "rolled_back"
				summary.RolledBackAt = performedAt
				message = firstNonEmpty(strings.TrimSpace(output), "upgrade rolled back")
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
					"canary_percent":  cfg.Upgrade.CanaryPercent,
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
		summary.ApplyCommand = strings.TrimSpace(cfg.Upgrade.ApplyCommand)
		summary.RollbackCommand = strings.TrimSpace(cfg.Upgrade.RollbackCommand)
		summary.CanaryPercent = cfg.Upgrade.CanaryPercent
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
				Version:          1,
				State:            "published",
				UpdatedAt:        now,
				PublishedAt:      now,
				ActiveRules:      rules,
				SigmaRuleIDs:     ruleIDs,
				DeploymentStatus: "local_applied",
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
			logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, "", req.Notes, "failed", err.Error())
			return api.PolicySummary{}, err
		}
		switch strings.ToLower(strings.TrimSpace(req.Action)) {
		case "validate_sigma", "dry_run_sigma":
			ruleID := strings.TrimSpace(req.RuleID)
			if ruleID == "" {
				ruleID = "inline"
			}
			if err := validateSigmaRuleYAML(req.RuleYAML); err != nil {
				policyAudit.record(req.Action, req.Actor, req.Role, ruleID, req.Notes, "failed", err.Error())
				logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, ruleID, req.Notes, "failed", err.Error())
				return api.PolicySummary{}, err
			}
			summary := toAPIPolicySummary(mgmtServer.PolicyCenter().Draft)
			summary.State = "validated"
			summary.Notes = "sigma rule dry-run passed; draft unchanged"
			policyAudit.record(req.Action, req.Actor, req.Role, ruleID, req.Notes, "validated", summary.Notes)
			logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, ruleID, req.Notes, "validated", summary.Notes)
			return summary, nil
		case "publish":
			if approvalRequired(cfg, "policy.publish") && !approvalBook.consumeApproved("policy.publish", req.Actor) {
				err := fmt.Errorf("policy.publish requires approval")
				policyAudit.record(req.Action, req.Actor, req.Role, "", req.Notes, "failed", err.Error())
				logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, "", req.Notes, "failed", err.Error())
				return api.PolicySummary{}, err
			}
			summary := toAPIPolicySummary(mgmtServer.PublishPolicyFor(req.Notes, mgmt.FleetFilter{Group: req.TargetGroup, Tag: req.TargetTag}))
			target := fmt.Sprintf("v%d", summary.Version)
			message := fmt.Sprintf("policy published with deployment status %s", summary.DeploymentStatus)
			policyAudit.record(req.Action, req.Actor, req.Role, target, req.Notes, "published", message)
			logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, target, req.Notes, "published", message)
			return summary, nil
		case "rollback":
			if approvalRequired(cfg, "policy.rollback") && !approvalBook.consumeApproved("policy.rollback", req.Actor) {
				err := fmt.Errorf("policy.rollback requires approval")
				policyAudit.record(req.Action, req.Actor, req.Role, fmt.Sprintf("v%d", req.TargetVersion), req.Notes, "failed", err.Error())
				logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, fmt.Sprintf("v%d", req.TargetVersion), req.Notes, "failed", err.Error())
				return api.PolicySummary{}, err
			}
			revision, err := mgmtServer.RollbackPolicyFor(req.TargetVersion, req.Notes, mgmt.FleetFilter{Group: req.TargetGroup, Tag: req.TargetTag})
			if err != nil {
				policyAudit.record(req.Action, req.Actor, req.Role, fmt.Sprintf("v%d", req.TargetVersion), req.Notes, "failed", err.Error())
				logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, fmt.Sprintf("v%d", req.TargetVersion), req.Notes, "failed", err.Error())
				return api.PolicySummary{}, err
			}
			summary := toAPIPolicySummary(revision)
			target := fmt.Sprintf("v%d", summary.Version)
			message := fmt.Sprintf("policy rolled back from v%d with deployment status %s", req.TargetVersion, summary.DeploymentStatus)
			policyAudit.record(req.Action, req.Actor, req.Role, target, req.Notes, "rolled_back", message)
			logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, target, req.Notes, "rolled_back", message)
			return summary, nil
		case "add_sigma", "update_sigma", "remove_sigma", "add_whitelist", "remove_whitelist", "clear_whitelist", "add_taint", "remove_taint":
			update, target, err := policyUpdateFromAction(req)
			if err != nil {
				policyAudit.record(req.Action, req.Actor, req.Role, target, req.Notes, "failed", err.Error())
				logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, target, req.Notes, "failed", err.Error())
				return api.PolicySummary{}, err
			}
			ack, err := mgmtServer.UpdatePolicy(context.Background(), update)
			if err != nil {
				policyAudit.record(req.Action, req.Actor, req.Role, target, req.Notes, "failed", err.Error())
				logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, target, req.Notes, "failed", err.Error())
				return api.PolicySummary{}, err
			}
			if !ack.Success {
				err := fmt.Errorf("%s", strings.TrimSpace(ack.Message))
				if err.Error() == "" {
					err = fmt.Errorf("policy update rejected")
				}
				policyAudit.record(req.Action, req.Actor, req.Role, target, req.Notes, "failed", err.Error())
				logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, target, req.Notes, "failed", err.Error())
				return api.PolicySummary{}, err
			}
			summary := toAPIPolicySummary(mgmtServer.PolicyCenter().Draft)
			status := "draft_updated"
			message := strings.TrimSpace(ack.Message)
			if message == "" {
				message = "policy draft updated"
			}
			policyAudit.record(req.Action, req.Actor, req.Role, target, req.Notes, status, message)
			logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, target, req.Notes, status, message)
			return summary, nil
		default:
			err := fmt.Errorf("unknown policy action %q", req.Action)
			policyAudit.record(req.Action, req.Actor, req.Role, "", req.Notes, "failed", err.Error())
			logControlAudit(auditStore, "policy", req.Action, req.Actor, req.Role, "", req.Notes, "failed", err.Error())
			return api.PolicySummary{}, err
		}
	})
	apiServer.SetPolicyBundleDownloadFunc(func(requestedVersion int, actor, role string) (api.PolicyBundleDownload, error) {
		if mgmtServer == nil {
			err := fmt.Errorf("mgmt server not available")
			policyAudit.record("policy_bundle_download", actor, role, "", "", "failed", err.Error())
			logControlAudit(auditStore, "policy", "policy_bundle_download", actor, role, "", "", "failed", err.Error())
			return api.PolicyBundleDownload{}, err
		}
		snapshot := mgmtServer.PolicyCenter()
		selected := snapshot.Current
		if requestedVersion > 0 {
			found := false
			if snapshot.Current.Version == requestedVersion {
				selected = snapshot.Current
				found = true
			} else {
				for _, item := range snapshot.History {
					if item.Version == requestedVersion {
						selected = item
						found = true
						break
					}
				}
			}
			if !found {
				err := fmt.Errorf("policy version %d not found", requestedVersion)
				policyAudit.record("policy_bundle_download", actor, role, fmt.Sprintf("v%d", requestedVersion), "", "failed", err.Error())
				logControlAudit(auditStore, "policy", "policy_bundle_download", actor, role, fmt.Sprintf("v%d", requestedVersion), "", "failed", err.Error())
				return api.PolicyBundleDownload{}, err
			}
		}
		if strings.TrimSpace(selected.BundlePath) == "" {
			err := fmt.Errorf("policy version %d has no bundle artifact", selected.Version)
			policyAudit.record("policy_bundle_download", actor, role, fmt.Sprintf("v%d", selected.Version), "", "failed", err.Error())
			logControlAudit(auditStore, "policy", "policy_bundle_download", actor, role, fmt.Sprintf("v%d", selected.Version), "", "failed", err.Error())
			return api.PolicyBundleDownload{}, err
		}
		if _, err := os.Stat(selected.BundlePath); err != nil {
			wrapped := fmt.Errorf("policy bundle unavailable: %w", err)
			policyAudit.record("policy_bundle_download", actor, role, fmt.Sprintf("v%d", selected.Version), "", "failed", wrapped.Error())
			logControlAudit(auditStore, "policy", "policy_bundle_download", actor, role, fmt.Sprintf("v%d", selected.Version), "", "failed", wrapped.Error())
			return api.PolicyBundleDownload{}, wrapped
		}
		target := fmt.Sprintf("v%d", selected.Version)
		message := "policy bundle downloaded"
		policyAudit.record("policy_bundle_download", actor, role, target, selected.BundleSHA256, "downloaded", message)
		logControlAudit(auditStore, "policy", "policy_bundle_download", actor, role, target, selected.BundleSHA256, "downloaded", message)
		return api.PolicyBundleDownload{
			Path:     selected.BundlePath,
			FileName: fmt.Sprintf("providapt-policy-v%d.json", selected.Version),
			SHA256:   selected.BundleSHA256,
			Version:  selected.Version,
		}, nil
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

	// ── gRPC management + telemetry server ──────────────
	mgmtCfg := &mgmt.ServerConfig{
		ListenAddr:      cfg.API.GRPC,
		EnableTLS:       cfg.TLS.Enable,
		StateFile:       filepath.Join(cfg.Output.Dir, "control-plane-state.json"),
		PolicyBundleDir: filepath.Join(cfg.Output.Dir, "policy-bundles"),
	}
	if cfg.TLS.Enable {
		mgmtCfg.CertFile = cfg.TLS.CertFile
		mgmtCfg.KeyFile = cfg.TLS.KeyFile
		mgmtCfg.CAFile = cfg.TLS.CAFile
		mgmtCfg.RequireClientCert = true
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
	logx.System().Info("mgmt gRPC server started", "addr", cfg.API.GRPC, "tls", cfg.TLS.Enable, "mtls", cfg.TLS.Enable)

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
	includeComms := make(map[string]struct{}, len(cfg.Capture.IncludeComms))
	for _, comm := range cfg.Capture.IncludeComms {
		if trimmed := strings.TrimSpace(comm); trimmed != "" {
			includeComms[trimmed] = struct{}{}
		}
	}
	metricsTicker := time.NewTicker(15 * time.Second)
	defer metricsTicker.Stop()

loop:
	for {
		select {
		case evt, ok := <-eventCh:
			if !ok {
				logx.System().Warn("collector event channel closed")
				eventCh = nil
				continue
			}
			if evt == nil {
				logx.System().Warn("collector emitted nil event")
				continue
			}
			if len(includeComms) > 0 {
				if _, ok := includeComms[evt.Comm]; !ok {
					continue
				}
			}
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

		case err, ok := <-errCh:
			if !ok {
				logx.System().Warn("collector error channel closed")
				errCh = nil
				continue
			}
			if err != nil {
				logx.System().Error("collector error", "error", err)
			}

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
				includeComms = make(map[string]struct{}, len(newCfg.Capture.IncludeComms))
				for _, comm := range newCfg.Capture.IncludeComms {
					if trimmed := strings.TrimSpace(comm); trimmed != "" {
						includeComms[trimmed] = struct{}{}
					}
				}

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

func formatTimePtr(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func pathWithin(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	if candidateAbs == rootAbs {
		return true
	}
	return strings.HasPrefix(candidateAbs, rootAbs+string(os.PathSeparator))
}

func startBackupScheduler(cfg *config.Config, run func(api.BackupActionRequest) (api.BackupActionResult, error)) func() {
	if cfg == nil || run == nil || !cfg.Backup.Enabled {
		return func() {}
	}
	interval, err := time.ParseDuration(strings.TrimSpace(cfg.Backup.Interval))
	if err != nil || interval <= 0 {
		logx.System().Warn("automatic backup disabled: invalid interval", "interval", cfg.Backup.Interval, "error", err)
		return func() {}
	}
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		logx.System().Info("automatic backup scheduler started",
			"interval", interval.String(),
			"retain_archives", cfg.Backup.RetainArchives,
			"min_free_bytes", cfg.Backup.MinFreeBytes,
		)
		for {
			select {
			case <-ticker.C:
				if err := ensureBackupDiskFree(cfg.Output.Dir, cfg.Backup.MinFreeBytes); err != nil {
					logx.System().Warn("automatic backup skipped", "error", err)
					continue
				}
				result, err := run(api.BackupActionRequest{
					Action: "create",
					Actor:  "system:auto-backup",
					Role:   api.RoleAdmin,
					Note:   "scheduled backup",
				})
				if err != nil {
					logx.System().Warn("automatic backup failed", "error", err)
					continue
				}
				if cfg.Backup.RetainArchives >= 0 {
					if cleanupErr := backup.CleanupArchives(filepath.Dir(result.BackupPath), cfg.Backup.RetainArchives); cleanupErr != nil {
						logx.System().Warn("automatic backup cleanup failed", "error", cleanupErr)
					}
				}
				logx.System().Info("automatic backup completed", "path", result.BackupPath, "size_bytes", result.SizeBytes)
			case <-stopCh:
				logx.System().Info("automatic backup scheduler stopped")
				return
			}
		}
	}()
	return func() {
		close(stopCh)
	}
}

func ensureBackupDiskFree(path string, minFreeBytes int64) error {
	if minFreeBytes <= 0 {
		return nil
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("statfs %s: %w", path, err)
	}
	freeBytes := int64(stat.Bavail) * int64(stat.Bsize)
	if freeBytes < minFreeBytes {
		return fmt.Errorf("free disk %d below configured minimum %d", freeBytes, minFreeBytes)
	}
	return nil
}

func writeRestoreCutoverPlan(outputDir, restorePath string) (string, error) {
	if !pathWithin(outputDir, restorePath) {
		return "", fmt.Errorf("restore path must stay within output dir")
	}
	planDir := filepath.Join(outputDir, "restore-staging")
	if err := os.MkdirAll(planDir, 0700); err != nil {
		return "", fmt.Errorf("create restore plan dir: %w", err)
	}
	storePath := filepath.Join(outputDir, "store")
	backupPath := storePath + ".pre-restore-" + time.Now().UTC().Format("20060102T150405Z")
	planPath := filepath.Join(planDir, "activate-restore-"+time.Now().UTC().Format("20060102T150405Z")+".sh")
	script := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

systemctl stop providapt.service
test -d %q
if [ -e %q ]; then
  mv %q %q
fi
mv %q %q
systemctl start providapt.service
systemctl status providapt.service --no-pager
echo "ProvidAPT restore cutover complete. Previous store: %s"
`, restorePath, storePath, storePath, backupPath, restorePath, storePath, backupPath)
	if err := os.WriteFile(planPath, []byte(script), 0700); err != nil {
		return "", fmt.Errorf("write restore cutover plan: %w", err)
	}
	return planPath, nil
}

func loadAppliedPolicyVersion(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var state appliedPolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		return 0, err
	}
	return state.Version, nil
}

func saveAppliedPolicyVersion(path string, version int, ack, bundleSHA256, bundlePath string) error {
	if version <= 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	state := appliedPolicyState{
		Version:       version,
		BundleSHA256:  strings.TrimSpace(bundleSHA256),
		BundlePath:    strings.TrimSpace(bundlePath),
		LastAck:       strings.TrimSpace(ack),
		LastApplied:   time.Now().UTC().Format(time.RFC3339),
		SchemaVersion: 1,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

type appliedPolicyBundleResult struct {
	Path   string
	SHA256 string
}

func resolvePolicyEndpoint(policyEndpoint, telemetryEndpoint string) string {
	if endpoint := strings.TrimSpace(policyEndpoint); endpoint != "" {
		return strings.TrimRight(endpoint, "/")
	}
	endpoint := strings.TrimSpace(telemetryEndpoint)
	if endpoint == "" {
		return ""
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "http://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	host := parsed.Hostname()
	return "http://" + net.JoinHostPort(host, "8080")
}

func fetchAndApplyPolicyBundle(ctx context.Context, cfg agentPolicyClientConfig, version int, apt *analyzer.Analyzer, ctrl interface {
	ExcludePID(uint32) error
	ExcludeComms([]string) (int, error)
	AddHotPath(string) error
}) (appliedPolicyBundleResult, error) {
	if version <= 0 {
		return appliedPolicyBundleResult{}, fmt.Errorf("invalid policy version %d", version)
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return appliedPolicyBundleResult{}, fmt.Errorf("policy endpoint is not configured")
	}
	endpoint := strings.TrimRight(cfg.Endpoint, "/") + "/api/v1/control/policies/bundle?version=" + url.QueryEscape(strconv.Itoa(version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return appliedPolicyBundleResult{}, err
	}
	if key := strings.TrimSpace(cfg.APIKey); key != "" {
		req.Header.Set("X-API-Key", key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return appliedPolicyBundleResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return appliedPolicyBundleResult{}, fmt.Errorf("download policy bundle: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return appliedPolicyBundleResult{}, err
	}
	sum := sha256.Sum256(data)
	actualSHA := hex.EncodeToString(sum[:])
	expectedSHA := strings.TrimSpace(resp.Header.Get("X-Policy-Bundle-SHA256"))
	if expectedSHA != "" && !strings.EqualFold(expectedSHA, actualSHA) {
		return appliedPolicyBundleResult{}, fmt.Errorf("policy bundle checksum mismatch: expected %s got %s", expectedSHA, actualSHA)
	}
	var bundle agentPolicyBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return appliedPolicyBundleResult{}, fmt.Errorf("decode policy bundle: %w", err)
	}
	if bundle.Version != version {
		return appliedPolicyBundleResult{}, fmt.Errorf("policy bundle version mismatch: expected %d got %d", version, bundle.Version)
	}
	if err := applyPolicyBundle(bundle, apt, ctrl); err != nil {
		return appliedPolicyBundleResult{}, err
	}
	if strings.TrimSpace(cfg.BundleDir) == "" {
		return appliedPolicyBundleResult{SHA256: actualSHA}, nil
	}
	if err := os.MkdirAll(cfg.BundleDir, 0750); err != nil {
		return appliedPolicyBundleResult{}, err
	}
	path := filepath.Join(cfg.BundleDir, fmt.Sprintf("policy-v%d.json", version))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return appliedPolicyBundleResult{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return appliedPolicyBundleResult{}, err
	}
	return appliedPolicyBundleResult{Path: path, SHA256: actualSHA}, nil
}

func applyPolicyBundle(bundle agentPolicyBundle, apt *analyzer.Analyzer, ctrl interface {
	ExcludePID(uint32) error
	ExcludeComms([]string) (int, error)
	AddHotPath(string) error
}) error {
	if apt != nil {
		desired := map[string]struct{}{}
		for ruleID, ruleYAML := range bundle.SigmaRules {
			ruleID = strings.TrimSpace(ruleID)
			if ruleID == "" {
				continue
			}
			parsed, err := sigma.ParseRule([]byte(ruleYAML))
			if err != nil {
				return fmt.Errorf("parse sigma rule %s: %w", ruleID, err)
			}
			apt.AddSigmaRule(ruleID, parsed)
			desired[ruleID] = struct{}{}
		}
		for _, existing := range apt.SigmaRuleIDs() {
			if _, ok := desired[existing]; !ok {
				apt.RemoveSigmaRule(existing)
			}
		}
	}
	if ctrl != nil {
		comms := []string{}
		for _, key := range bundle.WhitelistKeys {
			kind, value, ok := strings.Cut(key, ":")
			if !ok || strings.TrimSpace(value) == "" {
				continue
			}
			switch strings.TrimSpace(kind) {
			case "pid":
				pid, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
				if err == nil {
					_ = ctrl.ExcludePID(uint32(pid))
				}
			case "comm":
				comms = append(comms, strings.TrimSpace(value))
			case "path":
				_ = ctrl.AddHotPath(strings.TrimSpace(value))
			}
		}
		if len(comms) > 0 {
			if _, err := ctrl.ExcludeComms(comms); err != nil {
				return fmt.Errorf("apply whitelist comms: %w", err)
			}
		}
	}
	for _, source := range bundle.TaintSources {
		_, label, hasLabel := strings.Cut(source, "|")
		if hasLabel && strings.TrimSpace(label) != "" {
			analyzer.AddUntrustedComm(strings.TrimSpace(label))
		}
	}
	return nil
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
		DeploymentStatus: revision.DeploymentStatus,
		TargetGroup:      revision.TargetGroup,
		TargetTag:        revision.TargetTag,
		TargetAgents:     revision.TargetAgents,
		AckedAgents:      revision.AckedAgents,
		PendingAgents:    revision.PendingAgents,
		BundlePath:       revision.BundlePath,
		BundleSHA256:     revision.BundleSHA256,
	}
	if !revision.UpdatedAt.IsZero() {
		summary.UpdatedAt = revision.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if !revision.PublishedAt.IsZero() {
		summary.PublishedAt = revision.PublishedAt.UTC().Format(time.RFC3339)
	}
	return summary
}

func policyUpdateFromAction(req api.PolicyActionRequest) (*mgmtpb.PolicyUpdate, string, error) {
	action := strings.ToLower(strings.TrimSpace(req.Action))
	switch action {
	case "add_sigma", "update_sigma", "remove_sigma":
		ruleID := strings.TrimSpace(req.RuleID)
		if ruleID == "" {
			return nil, "", fmt.Errorf("rule_id is required")
		}
		ruleAction := strings.TrimSuffix(action, "_sigma")
		if ruleAction == "add" || ruleAction == "update" {
			if strings.TrimSpace(req.RuleYAML) == "" {
				return nil, ruleID, fmt.Errorf("rule_yaml is required")
			}
		}
		return &mgmtpb.PolicyUpdate{
			Update: &mgmtpb.PolicyUpdate_Sigma{
				Sigma: &mgmtpb.SigmaRule{
					Action:   ruleAction,
					RuleId:   ruleID,
					RuleYaml: req.RuleYAML,
				},
			},
		}, ruleID, nil
	case "add_whitelist", "remove_whitelist", "clear_whitelist":
		whitelistAction := strings.TrimSuffix(action, "_whitelist")
		target := strings.TrimSpace(req.WhitelistTarget)
		value := strings.TrimSpace(req.WhitelistValue)
		if whitelistAction == "clear" {
			target = "path"
			value = "*"
		} else {
			if target == "" {
				return nil, "", fmt.Errorf("whitelist_target is required")
			}
			if value == "" {
				return nil, target, fmt.Errorf("whitelist_value is required")
			}
		}
		return &mgmtpb.PolicyUpdate{
			Update: &mgmtpb.PolicyUpdate_Whitelist{
				Whitelist: &mgmtpb.WhitelistUpdate{
					Action: whitelistAction,
					Target: target,
					Value:  value,
				},
			},
		}, target + ":" + value, nil
	case "add_taint", "remove_taint":
		prefix := strings.TrimSpace(req.TaintPrefix)
		if prefix == "" {
			return nil, "", fmt.Errorf("taint_prefix is required")
		}
		return &mgmtpb.PolicyUpdate{
			Update: &mgmtpb.PolicyUpdate_TaintSource{
				TaintSource: &mgmtpb.TaintSource{
					Action:   strings.TrimSuffix(action, "_taint"),
					IpPrefix: prefix,
					Label:    strings.TrimSpace(req.TaintLabel),
				},
			},
		}, prefix, nil
	default:
		return nil, "", fmt.Errorf("unsupported policy edit action %q", req.Action)
	}
}

func validateSigmaRuleYAML(ruleYAML string) error {
	trimmed := strings.TrimSpace(ruleYAML)
	if trimmed == "" {
		return fmt.Errorf("rule_yaml is required")
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(trimmed), &doc); err != nil {
		return fmt.Errorf("parse sigma yaml: %w", err)
	}
	for _, key := range []string{"title", "detection"} {
		if _, ok := doc[key]; !ok {
			return fmt.Errorf("sigma rule missing %s", key)
		}
	}
	if detection, ok := doc["detection"].(map[string]interface{}); ok {
		if _, ok := detection["condition"]; !ok {
			return fmt.Errorf("sigma rule detection missing condition")
		}
	}
	return nil
}

func parseTimeOrZero(raw string) time.Time {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func complianceRecommendations(status api.ComplianceStatus) []string {
	out := []string{}
	if status.RetentionDays == 0 {
		out = append(out, "set a non-zero audit retention window")
	}
	if status.AuditEntries == 0 {
		out = append(out, "verify audit ingestion before production release")
	}
	if status.SIEM.Enabled && status.SIEM.LastStatus == "" {
		out = append(out, "run a SIEM test event before handoff")
	}
	if status.Approvals.Enabled && len(status.Approvals.Pending) > 0 {
		out = append(out, "review pending change approvals")
	}
	return out
}

func complianceReadiness(status api.ComplianceStatus) (int, string) {
	score := 100
	if status.RetentionDays == 0 {
		score -= 20
	}
	if status.AuditEntries == 0 {
		score -= 20
	}
	if status.SIEM.Enabled && status.SIEM.LastStatus == "" {
		score -= 15
	}
	if status.SIEM.Enabled && status.SIEM.LastError != "" {
		score -= 20
	}
	if status.Approvals.Enabled && len(status.Approvals.Pending) > 0 {
		score -= 10
	}
	if score < 0 {
		score = 0
	}
	switch {
	case score >= 90:
		return score, "A"
	case score >= 75:
		return score, "B"
	case score >= 60:
		return score, "C"
	default:
		return score, "D"
	}
}

func approvalRequired(cfg *config.Config, action string) bool {
	if cfg == nil || !cfg.Compliance.RequireApprovals {
		return false
	}
	action = strings.TrimSpace(action)
	for _, required := range cfg.Compliance.ApprovalActions {
		if strings.EqualFold(strings.TrimSpace(required), action) {
			return true
		}
	}
	return false
}

func approvalTTL(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 24 * time.Hour
	}
	ttl, err := time.ParseDuration(firstNonEmpty(strings.TrimSpace(cfg.Compliance.ApprovalTTL), "24h"))
	if err != nil || ttl <= 0 {
		return 24 * time.Hour
	}
	return ttl
}

func startAuditRetentionScheduler(cfg *config.Config, auditStore *audit.Store, state *complianceState) func() {
	if cfg == nil || auditStore == nil || cfg.Compliance.RetentionDays <= 0 {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		_, _ = applyAuditRetention(auditStore, cfg, state)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, err := applyAuditRetention(auditStore, cfg, state); err != nil {
					log.Printf("[compliance] audit retention failed: %v", err)
				}
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

func startComplianceReportScheduler(cfg *config.Config, reportDir func() string, buildStatus func() api.ComplianceStatus, state *complianceState) func() {
	if cfg == nil || reportDir == nil || buildStatus == nil {
		return func() {}
	}
	intervalText := strings.TrimSpace(cfg.Compliance.ReportInterval)
	if intervalText == "" {
		return func() {}
	}
	interval, err := time.ParseDuration(intervalText)
	if err != nil || interval <= 0 {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				status := buildStatus()
				path, err := writeComplianceHTMLReport(reportDir(), status)
				if err != nil {
					log.Printf("[compliance] scheduled report failed: %v", err)
					continue
				}
				if state != nil {
					status.LastReportPath = path
					status.LastActionStatus = "completed"
					status.LastActionMessage = "scheduled compliance report generated"
					state.update(status)
				}
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

func applyAuditRetention(auditStore *audit.Store, cfg *config.Config, state *complianceState) (audit.RetentionResult, error) {
	if auditStore == nil || cfg == nil {
		return audit.RetentionResult{}, nil
	}
	archiveDir := strings.TrimSpace(cfg.Compliance.ReportDir)
	if archiveDir == "" {
		archiveDir = filepath.Join(cfg.Output.Dir, "compliance")
	}
	archiveDir = filepath.Join(archiveDir, "audit-archive")
	result, err := auditStore.ApplyRetention(cfg.Compliance.RetentionDays, archiveDir, time.Now().UTC())
	if err != nil {
		return result, err
	}
	if state != nil {
		status := state.snapshot()
		status.LastRetentionAt = time.Now().UTC().Format(time.RFC3339)
		status.LastArchivePath = result.ArchivePath
		status.LastArchivedCount = result.Archived
		status.LastActionStatus = "completed"
		status.LastActionMessage = fmt.Sprintf("audit retention applied; archived %d entrie(s)", result.Archived)
		state.update(status)
	}
	return result, nil
}

func startSIEMForwarder(cfg *config.Config, outboxPath string, state *complianceState) func() {
	if cfg == nil {
		return func() {}
	}
	stop := make(chan struct{})
	interval, err := time.ParseDuration(firstNonEmpty(strings.TrimSpace(cfg.SIEM.FlushInterval), "30s"))
	if err != nil || interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				status, err := forwardSIEMOutbox(cfg, outboxPath)
				if err != nil {
					log.Printf("[siem] forward failed: %v", err)
				}
				if state != nil && status.LastStatus != "" {
					summary := state.snapshot()
					summary.SIEM = status
					state.update(summary)
				}
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

func forwardSIEMOutbox(cfg *config.Config, outboxPath string) (api.SIEMStatus, error) {
	status := api.SIEMStatus{
		Enabled:     cfg.SIEM.Enabled,
		Provider:    firstNonEmpty(strings.TrimSpace(cfg.SIEM.Provider), "generic"),
		Endpoint:    strings.TrimSpace(cfg.SIEM.Endpoint),
		Format:      firstNonEmpty(strings.TrimSpace(cfg.SIEM.Format), "json"),
		MinSeverity: firstNonEmpty(strings.TrimSpace(cfg.SIEM.MinSeverity), "INFO"),
		OutboxPath:  outboxPath,
	}
	if !cfg.SIEM.Enabled {
		status.LastStatus = "disabled"
		return status, nil
	}
	if status.Endpoint == "" {
		status.LastStatus = "failed"
		status.LastError = "siem.endpoint is required"
		return status, fmt.Errorf("%s", status.LastError)
	}
	data, err := os.ReadFile(outboxPath)
	if err != nil {
		if os.IsNotExist(err) {
			status.LastStatus = "idle"
			return status, nil
		}
		status.LastStatus = "failed"
		status.LastError = err.Error()
		return status, err
	}
	lines := nonEmptyLines(string(data))
	if len(lines) == 0 {
		status.LastStatus = "idle"
		return status, nil
	}
	if err := deliverSIEMLines(cfg, lines); err != nil {
		status.LastStatus = "failed"
		status.LastError = err.Error()
		return status, err
	}
	if err := os.WriteFile(outboxPath, nil, 0600); err != nil {
		status.LastStatus = "failed"
		status.LastError = err.Error()
		return status, err
	}
	status.ForwardedEvents = len(lines)
	status.LastForwardedAt = time.Now().UTC().Format(time.RFC3339)
	status.LastStatus = "forwarded"
	return status, nil
}

func deliverSIEMLines(cfg *config.Config, lines []string) error {
	endpoint := strings.TrimSpace(cfg.SIEM.Endpoint)
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	provider := strings.ToLower(firstNonEmpty(strings.TrimSpace(cfg.SIEM.Provider), "generic"))
	if provider == "splunk" || parsed.Scheme == "splunk" {
		return deliverSplunkHEC(endpoint, cfg.SIEM.Token, cfg.SIEM.Index, cfg.SIEM.SourceType, lines)
	}
	if provider == "elastic" || parsed.Scheme == "elastic" {
		return deliverElasticBulk(endpoint, cfg.SIEM.Token, cfg.SIEM.Index, lines)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "file":
		path := parsed.Path
		if path == "" {
			path = strings.TrimPrefix(endpoint, "file://")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		for _, line := range lines {
			if _, err := f.WriteString(line + "\n"); err != nil {
				return err
			}
		}
		return nil
	case "http", "https":
		client := &http.Client{Timeout: 10 * time.Second}
		for _, line := range lines {
			req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(line))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return fmt.Errorf("siem endpoint returned %d", resp.StatusCode)
			}
		}
		return nil
	case "tcp", "udp":
		conn, err := net.DialTimeout(parsed.Scheme, parsed.Host, 10*time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()
		for _, line := range lines {
			if _, err := conn.Write([]byte(line + "\n")); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported SIEM endpoint scheme %q", parsed.Scheme)
	}
}

func deliverSplunkHEC(endpoint, token, index, sourceType string, lines []string) error {
	endpoint = strings.TrimPrefix(strings.TrimSpace(endpoint), "splunk://")
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("splunk HEC endpoint is required")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for _, line := range lines {
		payload := map[string]interface{}{
			"event": line,
		}
		if strings.TrimSpace(index) != "" {
			payload["index"] = strings.TrimSpace(index)
		}
		if strings.TrimSpace(sourceType) != "" {
			payload["sourcetype"] = strings.TrimSpace(sourceType)
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(body)))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if strings.TrimSpace(token) != "" {
			req.Header.Set("Authorization", "Splunk "+strings.TrimSpace(token))
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("splunk HEC returned %d", resp.StatusCode)
		}
	}
	return nil
}

func deliverElasticBulk(endpoint, token, index string, lines []string) error {
	endpoint = strings.TrimPrefix(strings.TrimSpace(endpoint), "elastic://")
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("elastic endpoint is required")
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}
	targetIndex := firstNonEmpty(strings.TrimSpace(index), "providapt-events")
	var builder strings.Builder
	for _, line := range lines {
		meta, _ := json.Marshal(map[string]interface{}{"index": map[string]interface{}{"_index": targetIndex}})
		builder.Write(meta)
		builder.WriteByte('\n')
		if strings.HasPrefix(strings.TrimSpace(line), "{") {
			builder.WriteString(line)
		} else {
			wrapped, _ := json.Marshal(map[string]interface{}{"message": line})
			builder.Write(wrapped)
		}
		builder.WriteByte('\n')
	}
	req, err := http.NewRequest(http.MethodPost, endpoint+"_bulk", strings.NewReader(builder.String()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "ApiKey "+strings.TrimSpace(token))
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("elastic bulk returned %d", resp.StatusCode)
	}
	return nil
}

func nonEmptyLines(text string) []string {
	raw := strings.Split(text, "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func exportAuditEvidence(dir string, entries []audit.Entry, format string) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "csv"
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	switch format {
	case "json", "ndjson":
		path := filepath.Join(dir, "audit-evidence-"+stamp+".ndjson")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return "", err
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		for _, entry := range entries {
			if err := enc.Encode(entry); err != nil {
				return "", err
			}
		}
		return path, nil
	case "csv":
		path := filepath.Join(dir, "audit-evidence-"+stamp+".csv")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return "", err
		}
		defer f.Close()
		writer := csv.NewWriter(f)
		if err := writer.Write([]string{"id", "timestamp", "category", "severity", "source", "message", "details"}); err != nil {
			return "", err
		}
		for _, entry := range entries {
			details := ""
			if len(entry.Details) > 0 {
				data, err := json.Marshal(entry.Details)
				if err != nil {
					return "", err
				}
				details = string(data)
			}
			if err := writer.Write([]string{
				entry.ID,
				entry.Timestamp.UTC().Format(time.RFC3339),
				string(entry.Category),
				entry.Severity,
				entry.Source,
				entry.Message,
				details,
			}); err != nil {
				return "", err
			}
		}
		writer.Flush()
		return path, writer.Error()
	default:
		return "", fmt.Errorf("unsupported audit export format: %s", format)
	}
}

func writeComplianceReport(dir string, status api.ComplianceStatus) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	path := filepath.Join(dir, "compliance-report-"+time.Now().UTC().Format("20060102T150405Z")+".json")
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return "", err
	}
	return path, nil
}

func writeComplianceHTMLReport(dir string, status api.ComplianceStatus) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	path := filepath.Join(dir, "compliance-report-"+time.Now().UTC().Format("20060102T150405Z")+".html")
	escape := func(value string) string {
		replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
		return replacer.Replace(value)
	}
	rows := []string{
		fmt.Sprintf("<tr><th>Updated</th><td>%s</td></tr>", escape(status.UpdatedAt)),
		fmt.Sprintf("<tr><th>Tenant</th><td>%s</td></tr>", escape(firstNonEmpty(status.Tenant, "all"))),
		fmt.Sprintf("<tr><th>Readiness</th><td>%d / 100 · Grade %s</td></tr>", status.ReadinessScore, escape(status.ReadinessGrade)),
		fmt.Sprintf("<tr><th>Audit entries</th><td>%d</td></tr>", status.AuditEntries),
		fmt.Sprintf("<tr><th>Retention</th><td>%d days</td></tr>", status.RetentionDays),
		fmt.Sprintf("<tr><th>Last archive</th><td>%s (%d archived)</td></tr>", escape(status.LastArchivePath), status.LastArchivedCount),
		fmt.Sprintf("<tr><th>Last export</th><td>%s</td></tr>", escape(status.LastExportPath)),
		fmt.Sprintf("<tr><th>SIEM</th><td>%s · %s → %s</td></tr>", escape(firstNonEmpty(status.SIEM.Provider, "generic")), escape(status.SIEM.LastStatus), escape(status.SIEM.Endpoint)),
		fmt.Sprintf("<tr><th>Approvals</th><td>%d pending / %d total</td></tr>", len(status.Approvals.Pending), len(status.Approvals.History)),
	}
	recommendations := "None"
	if len(status.RecommendedActions) > 0 {
		parts := make([]string, 0, len(status.RecommendedActions))
		for _, item := range status.RecommendedActions {
			parts = append(parts, "<li>"+escape(item)+"</li>")
		}
		recommendations = "<ul>" + strings.Join(parts, "") + "</ul>"
	}
	body := "<!doctype html><html><head><meta charset=\"utf-8\"><title>ProvidAPT Compliance Report</title>" +
		"<style>body{font-family:Arial,sans-serif;margin:32px;color:#1f2937}h1{color:#0f62fe}table{border-collapse:collapse;width:100%;max-width:960px}th,td{border:1px solid #d0d7de;padding:8px;text-align:left}th{width:220px;background:#f6f8fa}.muted{color:#57606a}</style>" +
		"</head><body><h1>ProvidAPT Compliance Report</h1><p class=\"muted\">Generated for audit review and commercial release evidence.</p><table>" +
		strings.Join(rows, "") + "</table><h2>Recommended Actions</h2>" + recommendations + "</body></html>\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		return "", err
	}
	return path, nil
}

func writeSIEMTestEvent(cfg *config.Config, outboxPath, actor, note string) (api.SIEMStatus, error) {
	status := api.SIEMStatus{
		Enabled:     cfg.SIEM.Enabled,
		Provider:    firstNonEmpty(strings.TrimSpace(cfg.SIEM.Provider), "generic"),
		Endpoint:    strings.TrimSpace(cfg.SIEM.Endpoint),
		Format:      firstNonEmpty(strings.TrimSpace(cfg.SIEM.Format), "json"),
		MinSeverity: firstNonEmpty(strings.TrimSpace(cfg.SIEM.MinSeverity), "INFO"),
		OutboxPath:  outboxPath,
	}
	event := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"source":    "providapt",
		"kind":      "siem_test",
		"severity":  "INFO",
		"version":   version.String(),
		"actor":     strings.TrimSpace(actor),
		"note":      strings.TrimSpace(note),
	}
	if err := os.MkdirAll(filepath.Dir(outboxPath), 0700); err != nil {
		status.LastStatus = "failed"
		status.LastError = err.Error()
		return status, err
	}
	f, err := os.OpenFile(outboxPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		status.LastStatus = "failed"
		status.LastError = err.Error()
		return status, err
	}
	defer f.Close()
	var line []byte
	if strings.EqualFold(status.Format, "cef") {
		line = []byte(fmt.Sprintf("CEF:0|ProvidAPT|ProvidAPT|%s|siem_test|SIEM test event|1|act=%s msg=%s\n", version.String(), sanitizeCEF(actor), sanitizeCEF(note)))
	} else {
		line, err = json.Marshal(event)
		if err != nil {
			status.LastStatus = "failed"
			status.LastError = err.Error()
			return status, err
		}
		line = append(line, '\n')
	}
	if _, err := f.Write(line); err != nil {
		status.LastStatus = "failed"
		status.LastError = err.Error()
		return status, err
	}
	status.ForwardedEvents = 1
	status.LastForwardedAt = time.Now().UTC().Format(time.RFC3339)
	if !cfg.SIEM.Enabled {
		status.LastStatus = "queued_disabled"
		status.LastError = "siem.enabled is false; test event written to outbox only"
		return status, nil
	}
	status.LastStatus = "queued"
	return status, nil
}

func sanitizeCEF(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "=", "\\=")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return value
}

func logControlAudit(store *audit.Store, source, action, actor, role, target, note, status, message string) {
	if store == nil {
		return
	}
	severity := "INFO"
	if strings.EqualFold(status, "failed") {
		severity = "WARNING"
	}
	_ = store.Log(audit.Entry{
		Category: audit.CatAdmin,
		Severity: severity,
		Message:  message,
		Source:   source,
		Details: map[string]interface{}{
			"action": action,
			"actor":  actor,
			"role":   role,
			"target": target,
			"note":   note,
			"status": status,
		},
	})
}

func toAPIAlertWorkflowItem(item alertflow.Alert) api.AlertWorkflowItem {
	out := api.AlertWorkflowItem{
		ID:       item.ID,
		Severity: cleanWorkflowText(item.Severity),
		Pattern:  cleanWorkflowText(item.Pattern),
		Headline: cleanWorkflowText(item.Headline),
		Reason:   cleanWorkflowText(item.Reason),
		Source:   cleanWorkflowText(item.Source),
		Status:   string(item.Status),
		Assignee: cleanWorkflowText(item.Assignee),
		Count:    item.Count,
		Note:     cleanWorkflowText(item.Note),
		Details:  cleanWorkflowDetails(item.Details),
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
	if deadline, status, secondsLeft := alertWorkflowSLA(item); !deadline.IsZero() {
		out.SLADeadline = deadline.UTC().Format(time.RFC3339)
		out.SLAStatus = status
		out.SLASecondsLeft = secondsLeft
	}
	return out
}

func alertWorkflowSLA(item alertflow.Alert) (time.Time, string, int64) {
	if item.FirstSeen.IsZero() || item.Status == alertflow.StatusClosed {
		return time.Time{}, "", 0
	}
	duration := 24 * time.Hour
	switch strings.ToLower(strings.TrimSpace(item.Severity)) {
	case "critical":
		duration = 30 * time.Minute
	case "high":
		duration = 2 * time.Hour
	case "medium":
		duration = 8 * time.Hour
	case "low":
		duration = 24 * time.Hour
	}
	deadline := item.FirstSeen.Add(duration)
	secondsLeft := int64(time.Until(deadline).Seconds())
	status := "within_sla"
	if secondsLeft < 0 {
		status = "breached"
	} else if secondsLeft < int64((duration / 4).Seconds()) {
		status = "due_soon"
	}
	return deadline, status, secondsLeft
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

func cleanWorkflowDetails(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[cleanWorkflowText(key)] = cleanWorkflowText(value)
	}
	return out
}

func cleanWorkflowText(input string) string {
	arrowQuestion := mojibakeToken(0x922b, "?")
	arrowDash := mojibakeToken(0x922b, "-")
	dashQuestion := mojibakeToken(0x9225, "?")
	dashDash := mojibakeToken(0x9225, "-")
	legacyDash := mojibakeToken(0x95b3, "?")
	alertArrow := mojibakeToken(0x920c, "?")
	replacer := strings.NewReplacer(
		" "+arrowQuestion+" ", " -> ",
		" "+arrowQuestion, " -> ",
		arrowQuestion+" ", " -> ",
		arrowQuestion, "->",
		" "+arrowDash+" ", " -> ",
		" "+arrowDash, " -> ",
		arrowDash+" ", " -> ",
		arrowDash, "->",
		dashQuestion, "-",
		dashDash, "-",
		legacyDash, "-",
		" "+alertArrow+" ", " -> ",
		" "+alertArrow, " -> ",
		alertArrow+" ", " -> ",
		alertArrow, "->",
	)
	return replacer.Replace(input)
}

func mojibakeToken(codepoint rune, suffix string) string {
	return string(codepoint) + suffix
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
