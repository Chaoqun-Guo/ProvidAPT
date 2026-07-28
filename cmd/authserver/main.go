package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
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
}

type licenseDocument struct {
	ID                 string `json:"id"`
	Customer           string `json:"customer"`
	Edition            string `json:"edition"`
	MaxAgents          int    `json:"max_agents"`
	MachineFingerprint string `json:"machine_fingerprint,omitempty"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
	Signature          string `json:"signature"`
}

type activationResponse struct {
	Status      string          `json:"status"`
	Message     string          `json:"message,omitempty"`
	LicenseData string          `json:"license_data"`
	License     licenseDocument `json:"license"`
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

func main() {
	addr := getenv("PROVIDAPT_AUTH_ADDR", ":19090")
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/activate", handleActivate)
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
	expectedCode := strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_ACTIVATION_CODE"))
	if expectedCode != "" && !hmac.Equal([]byte(code), []byte(expectedCode)) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid activation code"})
		return
	}
	now := time.Now().UTC()
	validDays := firstPositive(req.ValidDays, envInt("PROVIDAPT_AUTH_VALID_DAYS", 365))
	customer := firstNonEmpty(req.Customer, os.Getenv("PROVIDAPT_AUTH_CUSTOMER"), "ProvidAPT Customer")
	edition := firstNonEmpty(req.Edition, os.Getenv("PROVIDAPT_AUTH_EDITION"), "enterprise")
	maxAgents := firstPositive(req.MaxAgents, envInt("PROVIDAPT_AUTH_MAX_AGENTS", 100))
	license := licenseDocument{
		ID:                 firstNonEmpty(os.Getenv("PROVIDAPT_AUTH_LICENSE_ID"), "lic-"+now.Format("20060102150405")),
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
	writeJSON(w, http.StatusOK, activationResponse{
		Status:      "issued",
		Message:     "license issued",
		LicenseData: string(data),
		License:     license,
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
	ids := strings.Split(os.Getenv("PROVIDAPT_AUTH_REVOKED_IDS"), ",")
	revoked := make([]string, 0, len(ids))
	for _, id := range ids {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			revoked = append(revoked, trimmed)
		}
	}
	writeJSON(w, http.StatusOK, revocationPayload{RevokedIDs: revoked, UpdatedAt: time.Now().UTC().Format(time.RFC3339)})
}

func withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(os.Getenv("PROVIDAPT_AUTH_API_KEY"))
		if token != "" && r.URL.Path != "/health" && !strings.HasPrefix(r.URL.Path, "/artifacts/") {
			got := strings.TrimPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
			if !hmac.Equal([]byte(got), []byte(token)) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func signLicense(doc licenseDocument, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(licenseSignaturePayload(doc)))
	return hex.EncodeToString(mac.Sum(nil))
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
