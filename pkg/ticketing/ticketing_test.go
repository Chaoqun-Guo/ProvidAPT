// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookClientCreateIssue(t *testing.T) {
	var got struct {
		Event   string        `json:"event"`
		Request CreateRequest `json:"request"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("auth header = %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := NewWebhookClient(srv.URL, "secret")
	issue, err := client.CreateIssue(CreateRequest{Title: "dead letter", Description: "details"})
	if err != nil {
		t.Fatalf("create issue: %v", err)
	}
	if issue.Provider != "webhook" {
		t.Fatalf("provider = %q", issue.Provider)
	}
	if got.Event != "providapt.ticket.create" {
		t.Fatalf("event = %q", got.Event)
	}
	if got.Request.Title != "dead letter" {
		t.Fatalf("title = %q", got.Request.Title)
	}
}

func TestWebhookClientAddComment(t *testing.T) {
	var got struct {
		Event   string `json:"event"`
		Comment string `json:"comment"`
		Issue   Issue  `json:"issue"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := NewWebhookClient(srv.URL, "")
	if err := client.AddComment(Issue{Provider: "webhook", URL: srv.URL, Key: "W-1"}, "delivery replayed"); err != nil {
		t.Fatalf("add comment: %v", err)
	}
	if got.Event != "providapt.ticket.comment" {
		t.Fatalf("event = %q", got.Event)
	}
	if got.Comment != "delivery replayed" {
		t.Fatalf("comment = %q", got.Comment)
	}
}

func TestJiraClientCreateIssue(t *testing.T) {
	var gotAuth string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"10001","key":"SEC-7","self":"` + srvURLPlaceholder + `"}`))
	}))
	defer srv.Close()

	client := NewJiraClient(srv.URL, "user@example.com", "token", "SEC", "Task")
	issue, err := client.CreateIssue(CreateRequest{
		Title:       "dead letter",
		Description: "details",
		Severity:    "CRITICAL",
	})
	if err != nil {
		t.Fatalf("create issue: %v", err)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user@example.com:token"))
	if gotAuth != wantAuth {
		t.Fatalf("auth = %q", gotAuth)
	}
	fields := gotBody["fields"].(map[string]interface{})
	if fields["summary"] != "dead letter" {
		t.Fatalf("summary = %v", fields["summary"])
	}
	if issue.Key != "SEC-7" {
		t.Fatalf("issue key = %q", issue.Key)
	}
}

func TestJiraClientAddComment(t *testing.T) {
	var gotAuth string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/rest/api/3/issue/SEC-7/comment" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	client := NewJiraClient(srv.URL, "user@example.com", "token", "SEC", "Task")
	if err := client.AddComment(Issue{Provider: "jira", Key: "SEC-7"}, "delivery replayed"); err != nil {
		t.Fatalf("add comment: %v", err)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user@example.com:token"))
	if gotAuth != wantAuth {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotBody["body"] != "delivery replayed" {
		t.Fatalf("body = %v", gotBody["body"])
	}
}

func TestServiceNowClientCreateIssue(t *testing.T) {
	var gotAuth string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"number":"INC0012345","sys_id":"abc123"}}`))
	}))
	defer srv.Close()

	client := NewServiceNowClient(srv.URL, "api-user", "secret", "incident")
	issue, err := client.CreateIssue(CreateRequest{
		Title:       "dead letter",
		Description: "details",
		Severity:    "HIGH",
		Metadata:    map[string]string{"delivery_id": "dlq-1"},
	})
	if err != nil {
		t.Fatalf("create issue: %v", err)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("api-user:secret"))
	if gotAuth != wantAuth {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotBody["short_description"] != "dead letter" {
		t.Fatalf("short_description = %v", gotBody["short_description"])
	}
	if issue.Key != "INC0012345" {
		t.Fatalf("issue key = %q", issue.Key)
	}
}

func TestServiceNowClientAddComment(t *testing.T) {
	var gotMethod string
	var gotPath string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":{"sys_id":"abc123"}}`))
	}))
	defer srv.Close()

	client := NewServiceNowClient(srv.URL, "api-user", "secret", "incident")
	err := client.AddComment(Issue{
		Provider: "servicenow",
		Key:      "INC0012345",
		URL:      srv.URL + "/nav_to.do?uri=incident.do?sys_id=abc123",
	}, "delivery replayed")
	if err != nil {
		t.Fatalf("add comment: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Fatalf("method = %q", gotMethod)
	}
	if gotPath != "/api/now/v1/table/incident/abc123" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotBody["comments"] != "delivery replayed" {
		t.Fatalf("comments = %v", gotBody["comments"])
	}
}

const srvURLPlaceholder = "http://jira.local/rest/api/3/issue/10001"
