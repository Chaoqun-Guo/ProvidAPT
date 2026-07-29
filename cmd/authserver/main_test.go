package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleActivateIssuesSignedLicense(t *testing.T) {
	t.Setenv("PROVIDAPT_AUTH_ACTIVATION_CODE", "trial-code")
	t.Setenv("PROVIDAPT_AUTH_LICENSE_SIGNING_KEY", "test-signing-key")
	t.Setenv("PROVIDAPT_AUTH_CUSTOMER", "Acme")
	t.Setenv("PROVIDAPT_AUTH_EDITION", "enterprise")
	t.Setenv("PROVIDAPT_AUTH_MAX_AGENTS", "42")

	body := bytes.NewBufferString(`{"activation_code":"trial-code","machine_fingerprint":"ABC123"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/activate", body)
	rec := httptest.NewRecorder()
	handleActivate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp activationResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "issued" || strings.TrimSpace(resp.LicenseData) == "" {
		t.Fatalf("unexpected activation response: %+v", resp)
	}
	if resp.License.Customer != "Acme" || resp.License.Edition != "enterprise" || resp.License.MaxAgents != 42 {
		t.Fatalf("unexpected license document: %+v", resp.License)
	}
	mac := hmac.New(sha256.New, []byte("test-signing-key"))
	_, _ = mac.Write([]byte(licenseSignaturePayload(resp.License)))
	expected := hex.EncodeToString(mac.Sum(nil))
	if resp.License.Signature != expected {
		t.Fatalf("signature = %q, want %q", resp.License.Signature, expected)
	}
}

func TestHandleActivateRejectsInvalidCode(t *testing.T) {
	t.Setenv("PROVIDAPT_AUTH_ACTIVATION_CODE", "trial-code")
	req := httptest.NewRequest(http.MethodPost, "/v1/activate", bytes.NewBufferString(`{"activation_code":"wrong"}`))
	rec := httptest.NewRecorder()
	handleActivate(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleActivateUsesCustomerRegistryAndWritesAudit(t *testing.T) {
	dir := t.TempDir()
	registryPath := filepath.Join(dir, "customers.json")
	statePath := filepath.Join(dir, "activations.jsonl")
	registry := `{"customers":[{"activation_code":"ACME-2026","customer":"Acme Corp","edition":"enterprise","license_id":"lic-acme","max_agents":250,"valid_days":730,"allowed_fingerprints":["FP-1"]}]}`
	if err := os.WriteFile(registryPath, []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	t.Setenv("PROVIDAPT_AUTH_CUSTOMER_REGISTRY", registryPath)
	t.Setenv("PROVIDAPT_AUTH_STATE_PATH", statePath)
	t.Setenv("PROVIDAPT_AUTH_LICENSE_SIGNING_KEY", "registry-key")

	req := httptest.NewRequest(http.MethodPost, "/v1/activate", bytes.NewBufferString(`{"activation_code":"ACME-2026","customer":"Override","max_agents":999,"machine_fingerprint":"FP-1"}`))
	rec := httptest.NewRecorder()
	handleActivate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp activationResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.License.ID != "lic-acme" || resp.License.Customer != "Acme Corp" || resp.License.MaxAgents != 250 {
		t.Fatalf("registry entitlement was not enforced: %+v", resp.License)
	}
	audit, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(string(audit), `"status":"issued"`) || !strings.Contains(string(audit), `"license_id":"lic-acme"`) {
		t.Fatalf("unexpected audit record: %s", string(audit))
	}
}

func TestHandleActivateRejectsRegistryFingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	registryPath := filepath.Join(dir, "customers.json")
	statePath := filepath.Join(dir, "activations.jsonl")
	registry := `{"customers":[{"activation_code":"ACME-2026","customer":"Acme Corp","allowed_fingerprints":["FP-1"]}]}`
	if err := os.WriteFile(registryPath, []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	t.Setenv("PROVIDAPT_AUTH_CUSTOMER_REGISTRY", registryPath)
	t.Setenv("PROVIDAPT_AUTH_STATE_PATH", statePath)

	req := httptest.NewRequest(http.MethodPost, "/v1/activate", bytes.NewBufferString(`{"activation_code":"ACME-2026","machine_fingerprint":"FP-2"}`))
	rec := httptest.NewRecorder()
	handleActivate(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	audit, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(string(audit), `"status":"rejected"`) || !strings.Contains(string(audit), "not entitled") {
		t.Fatalf("unexpected audit record: %s", string(audit))
	}
}

func TestHandleLatestReleaseUsesEnvironment(t *testing.T) {
	t.Setenv("PROVIDAPT_AUTH_RELEASE_VERSION", "v9.9.9")
	t.Setenv("PROVIDAPT_AUTH_UPGRADE_DOWNLOAD_URL", "https://downloads.example/providapt.tar.gz")
	t.Setenv("PROVIDAPT_AUTH_UPGRADE_SHA256", "abc123")

	req := httptest.NewRequest(http.MethodGet, "/v1/releases/latest", nil)
	rec := httptest.NewRecorder()
	handleLatestRelease(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var manifest releaseManifest
	if err := json.NewDecoder(rec.Body).Decode(&manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.Version != "v9.9.9" || manifest.DownloadURL == "" || manifest.ExpectedSHA256 != "abc123" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}

func TestHandleRevocationsMergesEnvironmentAndFile(t *testing.T) {
	dir := t.TempDir()
	revocationPath := filepath.Join(dir, "revocations.json")
	if err := os.WriteFile(revocationPath, []byte(`{"revoked_ids":["lic-file","lic-env"]}`), 0644); err != nil {
		t.Fatalf("write revocations: %v", err)
	}
	t.Setenv("PROVIDAPT_AUTH_REVOKED_IDS", "lic-env,lic-extra")
	t.Setenv("PROVIDAPT_AUTH_REVOCATION_FILE", revocationPath)

	req := httptest.NewRequest(http.MethodGet, "/v1/revocations", nil)
	rec := httptest.NewRecorder()
	handleRevocations(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload revocationPayload
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	got := strings.Join(payload.RevokedIDs, ",")
	for _, want := range []string{"lic-env", "lic-extra", "lic-file"} {
		if !strings.Contains(got, want) {
			t.Fatalf("revocations %q missing %q", got, want)
		}
	}
}
