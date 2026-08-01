package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type activationRequest struct {
	ActivationCode     string `json:"activation_code"`
	Customer           string `json:"customer"`
	Edition            string `json:"edition"`
	MaxAgents          int    `json:"max_agents"`
	MachineFingerprint string `json:"machine_fingerprint"`
	ValidDays          int    `json:"valid_days"`
	Note               string `json:"note,omitempty"`
}

type licenseDocument struct {
	ID                 string `json:"id"`
	ActivationKey      string `json:"activation_key,omitempty"`
	Customer           string `json:"customer"`
	Edition            string `json:"edition"`
	MaxAgents          int    `json:"max_agents"`
	MachineFingerprint string `json:"machine_fingerprint,omitempty"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
	Signature          string `json:"signature"`
}

type activationResponse struct {
	Status        string          `json:"status"`
	Message       string          `json:"message,omitempty"`
	RequestID     string          `json:"request_id,omitempty"`
	ActivationKey string          `json:"activation_key,omitempty"`
	LicenseData   string          `json:"license_data,omitempty"`
	License       licenseDocument `json:"license,omitempty"`
}

type releaseManifest struct {
	Version        string `json:"version"`
	DownloadURL    string `json:"download_url"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	SignatureURL   string `json:"signature_url,omitempty"`
	ReleaseNotes   string `json:"release_notes,omitempty"`
	PublishedAt    string `json:"published_at"`
	MinimumVersion string `json:"minimum_version,omitempty"`
}

type revocationPayload struct {
	RevokedIDs []string `json:"revoked_ids"`
	UpdatedAt  string   `json:"updated_at"`
}

type customerRegistry struct {
	Customers []customerEntitlement `json:"customers"`
}

type customerEntitlement struct {
	ActivationCode      string   `json:"activation_code"`
	Customer            string   `json:"customer"`
	Edition             string   `json:"edition"`
	LicenseID           string   `json:"license_id"`
	MaxAgents           int      `json:"max_agents"`
	ValidDays           int      `json:"valid_days"`
	AllowedFingerprints []string `json:"allowed_fingerprints"`
	Disabled            bool     `json:"disabled"`
}

type activationAuditRecord struct {
	Timestamp             string `json:"timestamp"`
	Status                string `json:"status"`
	Message               string `json:"message,omitempty"`
	LicenseID             string `json:"license_id,omitempty"`
	Customer              string `json:"customer,omitempty"`
	Edition               string `json:"edition,omitempty"`
	MaxAgents             int    `json:"max_agents,omitempty"`
	MachineFingerprint    string `json:"machine_fingerprint,omitempty"`
	ActivationCodeSHA256  string `json:"activation_code_sha256,omitempty"`
	ActivationKeySHA256   string `json:"activation_key_sha256,omitempty"`
	LicenseExpiresAt      string `json:"license_expires_at,omitempty"`
	RegistryEntitlementID string `json:"registry_entitlement_id,omitempty"`
}

type activationRequestRecord struct {
	ID                    string          `json:"id"`
	Status                string          `json:"status"`
	CreatedAt             string          `json:"created_at"`
	UpdatedAt             string          `json:"updated_at"`
	ApprovedAt            string          `json:"approved_at,omitempty"`
	RejectedAt            string          `json:"rejected_at,omitempty"`
	ApprovedBy            string          `json:"approved_by,omitempty"`
	RejectedBy            string          `json:"rejected_by,omitempty"`
	Message               string          `json:"message,omitempty"`
	ActivationCodeSHA256  string          `json:"activation_code_sha256,omitempty"`
	ActivationKeySHA256   string          `json:"activation_key_sha256,omitempty"`
	Customer              string          `json:"customer,omitempty"`
	Edition               string          `json:"edition,omitempty"`
	MaxAgents             int             `json:"max_agents,omitempty"`
	ValidDays             int             `json:"valid_days,omitempty"`
	MachineFingerprint    string          `json:"machine_fingerprint"`
	Note                  string          `json:"note,omitempty"`
	LicenseID             string          `json:"license_id,omitempty"`
	LicenseExpiresAt      string          `json:"license_expires_at,omitempty"`
	License               licenseDocument `json:"license,omitempty"`
	LicenseData           string          `json:"license_data,omitempty"`
	RegistryEntitlementID string          `json:"registry_entitlement_id,omitempty"`
}

type activationRequestList struct {
	Requests  []activationRequestRecord `json:"requests"`
	UpdatedAt string                    `json:"updated_at"`
}

type activationApprovalRequest struct {
	Action     string `json:"action,omitempty"`
	ApprovedBy string `json:"approved_by,omitempty"`
	Message    string `json:"message,omitempty"`
	Customer   string `json:"customer,omitempty"`
	Edition    string `json:"edition,omitempty"`
	MaxAgents  int    `json:"max_agents,omitempty"`
	ValidDays  int    `json:"valid_days,omitempty"`
	LicenseID  string `json:"license_id,omitempty"`
}

func main() {
	addr := getenv("PROVIDAPT_AUTH_ADDR", ":19090")
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/activate", handleActivate)
	mux.HandleFunc("/v1/activation-requests", handleActivationRequests)
	mux.HandleFunc("/v1/activation-requests/", handleActivationRequestByID)
	mux.HandleFunc("/v1/customers/status", handleCustomerStatus)
	mux.HandleFunc("/v1/releases/latest", handleLatestRelease)
	mux.HandleFunc("/v1/revocations", handleRevocations)
	mux.Handle("/artifacts/", http.StripPrefix("/artifacts/", http.FileServer(http.Dir(getenv("PROVIDAPT_AUTH_ARTIFACT_DIR", "/var/lib/providapt-auth/artifacts")))))
	log.Printf("providapt auth server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, withAuth(mux)))
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req activationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	code := strings.TrimSpace(req.ActivationCode)
	entitlement, registryEnabled, err := resolveEntitlement(code)
	if err != nil {
		writeActivationFailure(w, code, strings.TrimSpace(req.MachineFingerprint), err.Error())
		return
	}
	expectedCode := strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_ACTIVATION_CODE"))
	if !registryEnabled && expectedCode != "" && !hmac.Equal([]byte(code), []byte(expectedCode)) {
		writeActivationFailure(w, code, strings.TrimSpace(req.MachineFingerprint), "invalid activation code")
		return
	}
	if registryEnabled && !fingerprintAllowed(strings.TrimSpace(req.MachineFingerprint), entitlement.AllowedFingerprints) {
		writeActivationFailure(w, code, strings.TrimSpace(req.MachineFingerprint), "machine fingerprint is not entitled")
		return
	}
	if registryEnabled && entitlement.Disabled {
		writeActivationFailure(w, code, strings.TrimSpace(req.MachineFingerprint), "activation entitlement disabled")
		return
	}
	if registryEnabled && strings.TrimSpace(entitlement.ActivationCode) == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid activation code"})
		return
	}
	now := time.Now().UTC()
	validDays := firstPositive(entitlement.ValidDays, req.ValidDays, envInt("PROVIDAPT_AUTH_VALID_DAYS", 365))
	customer := firstNonEmpty(entitlement.Customer, req.Customer, os.Getenv("PROVIDAPT_AUTH_CUSTOMER"), "ProvidAPT Customer")
	edition := firstNonEmpty(entitlement.Edition, req.Edition, os.Getenv("PROVIDAPT_AUTH_EDITION"), "enterprise")
	maxAgents := firstPositive(entitlement.MaxAgents, req.MaxAgents, envInt("PROVIDAPT_AUTH_MAX_AGENTS", 100))
	license := licenseDocument{
		ID:                 firstNonEmpty(entitlement.LicenseID, os.Getenv("PROVIDAPT_AUTH_LICENSE_ID"), "lic-"+now.Format("20060102150405")),
		ActivationKey:      "act-" + randomHex(24),
		Customer:           customer,
		Edition:            edition,
		MaxAgents:          maxAgents,
		MachineFingerprint: strings.TrimSpace(req.MachineFingerprint),
		IssuedAt:           now.Format(time.RFC3339),
		ExpiresAt:          now.Add(time.Duration(validDays) * 24 * time.Hour).Format(time.RFC3339),
	}
	license.Signature = signLicense(license, getenv("PROVIDAPT_AUTH_LICENSE_SIGNING_KEY", getenv("PROVIDAPT_LICENSE_SIGNING_KEY", "providapt-dev-license-key")))
	data, err := json.MarshalIndent(license, "", "  ")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	appendActivationAudit(activationAuditRecord{
		Timestamp:             now.Format(time.RFC3339),
		Status:                "issued",
		Message:               "license issued",
		LicenseID:             license.ID,
		Customer:              license.Customer,
		Edition:               license.Edition,
		MaxAgents:             license.MaxAgents,
		MachineFingerprint:    license.MachineFingerprint,
		ActivationCodeSHA256:  sha256Hex(code),
		LicenseExpiresAt:      license.ExpiresAt,
		RegistryEntitlementID: firstNonEmpty(entitlement.LicenseID, entitlement.Customer),
	})
	writeJSON(w, http.StatusOK, activationResponse{
		Status:        "issued",
		Message:       "license issued",
		LicenseData:   string(data),
		ActivationKey: license.ActivationKey,
		License:       license,
	})
}

func handleActivationRequests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req activationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		fingerprint := strings.TrimSpace(req.MachineFingerprint)
		if fingerprint == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "machine_fingerprint is required"})
			return
		}
		code := strings.TrimSpace(req.ActivationCode)
		entitlement, registryEnabled, err := resolveEntitlementForRequest(code)
		if err != nil {
			writeActivationFailure(w, code, fingerprint, err.Error())
			return
		}
		if registryEnabled && !fingerprintAllowed(fingerprint, entitlement.AllowedFingerprints) {
			writeActivationFailure(w, code, fingerprint, "machine fingerprint is not entitled")
			return
		}
		now := time.Now().UTC()
		record := activationRequestRecord{
			ID:                    "actreq-" + randomHex(12),
			Status:                "pending",
			CreatedAt:             now.Format(time.RFC3339),
			UpdatedAt:             now.Format(time.RFC3339),
			Message:               "activation request pending approval",
			ActivationCodeSHA256:  sha256Hex(code),
			Customer:              firstNonEmpty(entitlement.Customer, req.Customer, os.Getenv("PROVIDAPT_AUTH_CUSTOMER"), "ProvidAPT Customer"),
			Edition:               firstNonEmpty(entitlement.Edition, req.Edition, os.Getenv("PROVIDAPT_AUTH_EDITION"), "enterprise"),
			MaxAgents:             firstPositive(entitlement.MaxAgents, req.MaxAgents, envInt("PROVIDAPT_AUTH_MAX_AGENTS", 100)),
			ValidDays:             firstPositive(entitlement.ValidDays, req.ValidDays, envInt("PROVIDAPT_AUTH_VALID_DAYS", 365)),
			MachineFingerprint:    fingerprint,
			Note:                  strings.TrimSpace(req.Note),
			LicenseID:             firstNonEmpty(entitlement.LicenseID, os.Getenv("PROVIDAPT_AUTH_LICENSE_ID")),
			RegistryEntitlementID: firstNonEmpty(entitlement.LicenseID, entitlement.Customer),
		}
		if err := upsertActivationRequest(record); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		appendActivationAudit(activationAuditRecord{
			Timestamp:             now.Format(time.RFC3339),
			Status:                "pending",
			Message:               "activation request pending approval",
			Customer:              record.Customer,
			Edition:               record.Edition,
			MaxAgents:             record.MaxAgents,
			MachineFingerprint:    fingerprint,
			ActivationCodeSHA256:  record.ActivationCodeSHA256,
			RegistryEntitlementID: record.RegistryEntitlementID,
		})
		writeJSON(w, http.StatusAccepted, activationResponse{
			Status:    "pending",
			Message:   "activation request pending approval",
			RequestID: record.ID,
		})
	case http.MethodGet:
		records, err := loadActivationRequests()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, activationRequestList{Requests: redactActivationRequestSecrets(records), UpdatedAt: time.Now().UTC().Format(time.RFC3339)})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func handleActivationRequestByID(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/activation-requests/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "activation request not found"})
		return
	}
	id := strings.TrimSpace(parts[0])
	if r.Method == http.MethodGet && len(parts) == 1 {
		record, ok, err := findActivationRequest(id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "activation request not found"})
			return
		}
		writeJSON(w, http.StatusOK, activationResponse{
			Status:      record.Status,
			Message:     record.Message,
			RequestID:   record.ID,
			LicenseData: record.LicenseData,
			License:     record.License,
		})
		return
	}
	if r.Method != http.MethodPost || len(parts) != 2 || (parts[1] != "approve" && parts[1] != "reject") {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req activationApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if parts[1] == "reject" || strings.EqualFold(req.Action, "reject") {
		record, err := rejectActivationRequest(id, req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, activationResponse{Status: record.Status, Message: record.Message, RequestID: record.ID})
		return
	}
	record, key, err := approveActivationRequest(id, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, activationResponse{
		Status:        record.Status,
		Message:       record.Message,
		RequestID:     record.ID,
		ActivationKey: key,
		LicenseData:   record.LicenseData,
		License:       record.License,
	})
}

func handleCustomerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	registry, err := loadCustomerRegistry(strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_CUSTOMER_REGISTRY")))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	revoked := collectRevokedIDs()
	disabled := 0
	for _, item := range registry.Customers {
		if item.Disabled {
			disabled++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":              "ok",
		"registry_configured": strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_CUSTOMER_REGISTRY")) != "",
		"entitlements":        len(registry.Customers),
		"disabled":            disabled,
		"revoked_ids":         len(revoked),
		"updated_at":          time.Now().UTC().Format(time.RFC3339),
	})
}

func handleLatestRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, releaseManifest{
		Version:        getenv("PROVIDAPT_AUTH_RELEASE_VERSION", "v1.2.3"),
		DownloadURL:    getenv("PROVIDAPT_AUTH_UPGRADE_DOWNLOAD_URL", "http://127.0.0.1:19090/artifacts/providapt.tar.gz"),
		ExpectedSHA256: os.Getenv("PROVIDAPT_AUTH_UPGRADE_SHA256"),
		SignatureURL:   os.Getenv("PROVIDAPT_AUTH_UPGRADE_SIGNATURE_URL"),
		ReleaseNotes:   os.Getenv("PROVIDAPT_AUTH_RELEASE_NOTES_URL"),
		PublishedAt:    getenv("PROVIDAPT_AUTH_RELEASE_PUBLISHED_AT", time.Now().UTC().Format(time.RFC3339)),
		MinimumVersion: os.Getenv("PROVIDAPT_AUTH_MINIMUM_VERSION"),
	})
}

func handleRevocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, revocationPayload{RevokedIDs: collectRevokedIDs(), UpdatedAt: time.Now().UTC().Format(time.RFC3339)})
}

func collectRevokedIDs() []string {
	ids := strings.Split(os.Getenv("PROVIDAPT_AUTH_REVOKED_IDS"), ",")
	revoked := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			seen[trimmed] = true
			revoked = append(revoked, trimmed)
		}
	}
	filePayload, err := loadRevocationFile(strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_REVOCATION_FILE")))
	if err == nil {
		for _, id := range filePayload.RevokedIDs {
			trimmed := strings.TrimSpace(id)
			if trimmed != "" && !seen[trimmed] {
				seen[trimmed] = true
				revoked = append(revoked, trimmed)
			}
		}
	}
	return revoked
}

func withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_API_KEY"))
		if token != "" && !isPublicAuthServerEndpoint(r) {
			got := strings.TrimPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
			if !hmac.Equal([]byte(got), []byte(token)) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isPublicAuthServerEndpoint(r *http.Request) bool {
	if r.URL.Path == "/health" || strings.HasPrefix(r.URL.Path, "/artifacts/") {
		return true
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/activation-requests" {
		return true
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/activation-requests/") {
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/activation-requests/"), "/")
		return path != "" && !strings.Contains(path, "/")
	}
	return false
}

func signLicense(doc licenseDocument, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(licenseSignaturePayload(doc)))
	return hex.EncodeToString(mac.Sum(nil))
}

func resolveEntitlement(code string) (customerEntitlement, bool, error) {
	registryPath := strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_CUSTOMER_REGISTRY"))
	if registryPath == "" {
		return customerEntitlement{}, false, nil
	}
	registry, err := loadCustomerRegistry(registryPath)
	if err != nil {
		return customerEntitlement{}, true, err
	}
	for _, entitlement := range registry.Customers {
		if hmac.Equal([]byte(strings.TrimSpace(entitlement.ActivationCode)), []byte(code)) {
			if entitlement.Disabled {
				return entitlement, true, errors.New("activation entitlement disabled")
			}
			return entitlement, true, nil
		}
	}
	return customerEntitlement{}, true, errors.New("invalid activation code")
}

func loadCustomerRegistry(path string) (customerRegistry, error) {
	if strings.TrimSpace(path) == "" {
		return customerRegistry{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return customerRegistry{}, err
	}
	var registry customerRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return customerRegistry{}, err
	}
	return registry, nil
}

func loadRevocationFile(path string) (revocationPayload, error) {
	if strings.TrimSpace(path) == "" {
		return revocationPayload{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return revocationPayload{}, err
	}
	var payload revocationPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return revocationPayload{}, err
	}
	return payload, nil
}

func resolveEntitlementForRequest(code string) (customerEntitlement, bool, error) {
	if strings.TrimSpace(code) == "" {
		if strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_CUSTOMER_REGISTRY")) != "" {
			return customerEntitlement{}, true, nil
		}
		return customerEntitlement{}, false, nil
	}
	return resolveEntitlement(code)
}

func activationRequestsPath() string {
	if path := strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_REQUESTS_PATH")); path != "" {
		return path
	}
	if statePath := strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_STATE_PATH")); statePath != "" {
		return filepath.Join(filepath.Dir(statePath), "activation-requests.json")
	}
	return "/var/lib/providapt-auth/activation-requests.json"
}

func loadActivationRequests() ([]activationRequestRecord, error) {
	path := activationRequestsPath()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return []activationRequestRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var payload activationRequestList
	if err := json.Unmarshal(data, &payload); err == nil && payload.Requests != nil {
		return payload.Requests, nil
	}
	var records []activationRequestRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func saveActivationRequests(records []activationRequestRecord) error {
	path := activationRequestsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(activationRequestList{Requests: records, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0640)
}

func upsertActivationRequest(record activationRequestRecord) error {
	records, err := loadActivationRequests()
	if err != nil {
		return err
	}
	for i := range records {
		if records[i].ID == record.ID {
			records[i] = record
			return saveActivationRequests(records)
		}
	}
	records = append(records, record)
	return saveActivationRequests(records)
}

func findActivationRequest(id string) (activationRequestRecord, bool, error) {
	records, err := loadActivationRequests()
	if err != nil {
		return activationRequestRecord{}, false, err
	}
	for _, record := range records {
		if record.ID == id {
			return record, true, nil
		}
	}
	return activationRequestRecord{}, false, nil
}

func approveActivationRequest(id string, req activationApprovalRequest) (activationRequestRecord, string, error) {
	records, err := loadActivationRequests()
	if err != nil {
		return activationRequestRecord{}, "", err
	}
	now := time.Now().UTC()
	for i := range records {
		if records[i].ID != id {
			continue
		}
		record := records[i]
		if record.Status == "approved" {
			return record, "", errors.New("activation request already approved")
		}
		if record.Status == "rejected" {
			return record, "", errors.New("activation request was rejected")
		}
		key := "act-" + randomHex(24)
		license := licenseDocument{
			ID:                 firstNonEmpty(req.LicenseID, record.LicenseID, "lic-"+now.Format("20060102150405")+"-"+randomHex(4)),
			ActivationKey:      key,
			Customer:           firstNonEmpty(req.Customer, record.Customer, os.Getenv("PROVIDAPT_AUTH_CUSTOMER"), "ProvidAPT Customer"),
			Edition:            firstNonEmpty(req.Edition, record.Edition, os.Getenv("PROVIDAPT_AUTH_EDITION"), "enterprise"),
			MaxAgents:          firstPositive(req.MaxAgents, record.MaxAgents, envInt("PROVIDAPT_AUTH_MAX_AGENTS", 100)),
			MachineFingerprint: record.MachineFingerprint,
			IssuedAt:           now.Format(time.RFC3339),
			ExpiresAt:          now.Add(time.Duration(firstPositive(req.ValidDays, record.ValidDays, envInt("PROVIDAPT_AUTH_VALID_DAYS", 365))) * 24 * time.Hour).Format(time.RFC3339),
		}
		license.Signature = signLicense(license, getenv("PROVIDAPT_AUTH_LICENSE_SIGNING_KEY", getenv("PROVIDAPT_LICENSE_SIGNING_KEY", "providapt-dev-license-key")))
		data, err := json.MarshalIndent(license, "", "  ")
		if err != nil {
			return activationRequestRecord{}, "", err
		}
		record.Status = "approved"
		record.UpdatedAt = now.Format(time.RFC3339)
		record.ApprovedAt = now.Format(time.RFC3339)
		record.ApprovedBy = firstNonEmpty(req.ApprovedBy, "license-admin")
		record.Message = firstNonEmpty(req.Message, "activation request approved and license issued")
		record.ActivationKeySHA256 = sha256Hex(key)
		record.LicenseID = license.ID
		record.LicenseExpiresAt = license.ExpiresAt
		record.License = license
		record.LicenseData = string(data)
		records[i] = record
		if err := saveActivationRequests(records); err != nil {
			return activationRequestRecord{}, "", err
		}
		appendActivationAudit(activationAuditRecord{
			Timestamp:             now.Format(time.RFC3339),
			Status:                "approved",
			Message:               record.Message,
			LicenseID:             license.ID,
			Customer:              license.Customer,
			Edition:               license.Edition,
			MaxAgents:             license.MaxAgents,
			MachineFingerprint:    license.MachineFingerprint,
			ActivationCodeSHA256:  record.ActivationCodeSHA256,
			ActivationKeySHA256:   record.ActivationKeySHA256,
			LicenseExpiresAt:      license.ExpiresAt,
			RegistryEntitlementID: record.RegistryEntitlementID,
		})
		return record, key, nil
	}
	return activationRequestRecord{}, "", errors.New("activation request not found")
}

func rejectActivationRequest(id string, req activationApprovalRequest) (activationRequestRecord, error) {
	records, err := loadActivationRequests()
	if err != nil {
		return activationRequestRecord{}, err
	}
	now := time.Now().UTC()
	for i := range records {
		if records[i].ID != id {
			continue
		}
		record := records[i]
		if record.Status == "approved" {
			return record, errors.New("activation request already approved")
		}
		record.Status = "rejected"
		record.UpdatedAt = now.Format(time.RFC3339)
		record.RejectedAt = now.Format(time.RFC3339)
		record.RejectedBy = firstNonEmpty(req.ApprovedBy, "license-admin")
		record.Message = firstNonEmpty(req.Message, "activation request rejected")
		records[i] = record
		if err := saveActivationRequests(records); err != nil {
			return activationRequestRecord{}, err
		}
		appendActivationAudit(activationAuditRecord{
			Timestamp:            now.Format(time.RFC3339),
			Status:               "rejected",
			Message:              record.Message,
			Customer:             record.Customer,
			Edition:              record.Edition,
			MaxAgents:            record.MaxAgents,
			MachineFingerprint:   record.MachineFingerprint,
			ActivationCodeSHA256: record.ActivationCodeSHA256,
		})
		return record, nil
	}
	return activationRequestRecord{}, errors.New("activation request not found")
}

func redactActivationRequestSecrets(records []activationRequestRecord) []activationRequestRecord {
	out := make([]activationRequestRecord, 0, len(records))
	for _, record := range records {
		record.LicenseData = ""
		record.License.ActivationKey = ""
		out = append(out, record)
	}
	return out
}

func randomHex(bytesLen int) string {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(buf)
}

func fingerprintAllowed(fingerprint string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, item := range allowed {
		if hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(item))), []byte(strings.ToLower(fingerprint))) {
			return true
		}
	}
	return false
}

func writeActivationFailure(w http.ResponseWriter, code, fingerprint, message string) {
	appendActivationAudit(activationAuditRecord{
		Timestamp:            time.Now().UTC().Format(time.RFC3339),
		Status:               "rejected",
		Message:              message,
		MachineFingerprint:   fingerprint,
		ActivationCodeSHA256: sha256Hex(code),
	})
	writeJSON(w, http.StatusForbidden, map[string]string{"error": message})
}

func appendActivationAudit(record activationAuditRecord) {
	statePath := strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_STATE_PATH"))
	if statePath == "" {
		return
	}
	data, err := json.Marshal(record)
	if err != nil {
		log.Printf("marshal activation audit: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0755); err != nil {
		log.Printf("create activation audit dir: %v", err)
		return
	}
	file, err := os.OpenFile(statePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		log.Printf("open activation audit: %v", err)
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("close activation audit: %v", err)
		}
	}()
	if _, err := file.Write(append(data, '\n')); err != nil {
		log.Printf("write activation audit: %v", err)
	}
}

func sha256Hex(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
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
	if strings.TrimSpace(doc.ActivationKey) != "" {
		parts = append([]string{parts[0], "activation_key=" + strings.TrimSpace(doc.ActivationKey)}, parts[1:]...)
	}
	if doc.MaxAgents > 0 {
		parts = append(parts, "max_agents="+strconv.Itoa(doc.MaxAgents))
	}
	return strings.Join(parts, "\n")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
