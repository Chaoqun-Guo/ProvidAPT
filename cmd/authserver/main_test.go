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

func TestActivationRequestApprovalIssuesUniqueLicenseKey(t *testing.T) {
	dir := t.TempDir()
	requestsPath := filepath.Join(dir, "activation-requests.json")
	auditPath := filepath.Join(dir, "activations.jsonl")
	t.Setenv("PROVIDAPT_AUTH_REQUESTS_PATH", requestsPath)
	t.Setenv("PROVIDAPT_AUTH_STATE_PATH", auditPath)
	t.Setenv("PROVIDAPT_AUTH_LICENSE_SIGNING_KEY", "approval-key")

	createReq := httptest.NewRequest(http.MethodPost, "/v1/activation-requests", bytes.NewBufferString(`{"customer":"Acme Corp","edition":"enterprise","machine_fingerprint":"FP-APPROVE","max_agents":25,"valid_days":90}`))
	createRec := httptest.NewRecorder()
	handleActivationRequests(createRec, createReq)
	if createRec.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
	}
	var created activationResponse
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Status != "pending" || created.RequestID == "" {
		t.Fatalf("unexpected create response: %+v", created)
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/v1/activation-requests/"+created.RequestID+"/approve", bytes.NewBufferString(`{"approved_by":"license-admin","message":"approved by back office"}`))
	approveRec := httptest.NewRecorder()
	handleActivationRequestByID(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve status = %d, body = %s", approveRec.Code, approveRec.Body.String())
	}
	var approved activationResponse
	if err := json.NewDecoder(approveRec.Body).Decode(&approved); err != nil {
		t.Fatalf("decode approval response: %v", err)
	}
	if approved.Status != "approved" || approved.ActivationKey == "" || strings.TrimSpace(approved.LicenseData) == "" {
		t.Fatalf("unexpected approval response: %+v", approved)
	}
	if approved.License.ActivationKey != approved.ActivationKey {
		t.Fatalf("license activation key mismatch")
	}
	mac := hmac.New(sha256.New, []byte("approval-key"))
	_, _ = mac.Write([]byte(licenseSignaturePayload(approved.License)))
	expected := hex.EncodeToString(mac.Sum(nil))
	if approved.License.Signature != expected {
		t.Fatalf("signature = %q, want %q", approved.License.Signature, expected)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/v1/activation-requests/"+created.RequestID, nil)
	statusRec := httptest.NewRecorder()
	handleActivationRequestByID(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", statusRec.Code, statusRec.Body.String())
	}
	var status activationResponse
	if err := json.NewDecoder(statusRec.Body).Decode(&status); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if status.Status != "approved" || !strings.Contains(status.LicenseData, approved.ActivationKey) {
		t.Fatalf("unexpected status response: %+v", status)
	}
}

func TestAuthServerProtectsActivationApproval(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROVIDAPT_AUTH_REQUESTS_PATH", filepath.Join(dir, "requests.json"))
	t.Setenv("PROVIDAPT_AUTH_API_KEY", "server-token")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/activation-requests", handleActivationRequests)
	mux.HandleFunc("/v1/activation-requests/", handleActivationRequestByID)
	handler := withAuth(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/activation-requests", bytes.NewBufferString(`{"machine_fingerprint":"FP-1"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("public create status = %d, body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/activation-requests/actreq-test/approve", bytes.NewBufferString(`{}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("approval without bearer status = %d, want %d", rec.Code, http.StatusUnauthorized)
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
