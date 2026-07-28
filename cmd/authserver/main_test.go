package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
