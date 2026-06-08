// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ServiceNowClient struct {
	baseURL  string
	username string
	password string
	table    string
	client   *http.Client
}

func NewServiceNowClient(baseURL, username, password, table string) *ServiceNowClient {
	if strings.TrimSpace(table) == "" {
		table = "incident"
	}
	return &ServiceNowClient{
		baseURL:  strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		username: strings.TrimSpace(username),
		password: strings.TrimSpace(password),
		table:    strings.TrimSpace(table),
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *ServiceNowClient) Provider() string { return "servicenow" }

type serviceNowRecord struct {
	ShortDescription string `json:"short_description"`
	Description      string `json:"description"`
	Severity         string `json:"severity,omitempty"`
	Category         string `json:"category,omitempty"`
	Subcategory      string `json:"subcategory,omitempty"`
	Comments         string `json:"comments,omitempty"`
}

type serviceNowCreateResponse struct {
	Result map[string]interface{} `json:"result"`
}

type serviceNowCommentPayload struct {
	Comments  string `json:"comments,omitempty"`
	WorkNotes string `json:"work_notes,omitempty"`
}

func (c *ServiceNowClient) CreateIssue(req CreateRequest) (Issue, error) {
	if c.baseURL == "" || c.username == "" || c.password == "" {
		return Issue{}, fmt.Errorf("servicenow client is not fully configured")
	}

	payload := serviceNowRecord{
		ShortDescription: req.Title,
		Description:      req.Description,
		Severity:         strings.ToLower(strings.TrimSpace(req.Severity)),
		Category:         "security",
		Subcategory:      "providapt",
	}
	if len(req.Metadata) > 0 {
		var comments strings.Builder
		comments.WriteString("ProvidAPT metadata:\n")
		for key, value := range req.Metadata {
			comments.WriteString(fmt.Sprintf("%s=%s\n", key, value))
		}
		payload.Comments = comments.String()
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return Issue{}, fmt.Errorf("marshal servicenow payload: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/now/v1/table/"+c.table, bytes.NewReader(body))
	if err != nil {
		return Issue{}, fmt.Errorf("build servicenow request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password)))

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return Issue{}, fmt.Errorf("servicenow create record: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return Issue{}, fmt.Errorf("servicenow create record returned %d", resp.StatusCode)
	}

	var created serviceNowCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return Issue{}, fmt.Errorf("decode servicenow response: %w", err)
	}

	key := ""
	if value, ok := created.Result["number"].(string); ok {
		key = value
	}
	url := c.baseURL
	if sysID, ok := created.Result["sys_id"].(string); ok && sysID != "" {
		url += "/nav_to.do?uri=" + c.table + ".do?sys_id=" + sysID
	}

	return Issue{
		Provider:  c.Provider(),
		Key:       key,
		URL:       url,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (c *ServiceNowClient) AddComment(issue Issue, comment string) error {
	if c.baseURL == "" || c.username == "" || c.password == "" {
		return fmt.Errorf("servicenow client is not fully configured")
	}
	sysID := extractServiceNowSysID(issue.URL)
	if sysID == "" {
		return fmt.Errorf("servicenow sys_id is required for comments")
	}
	payload, err := json.Marshal(serviceNowCommentPayload{
		Comments:  comment,
		WorkNotes: comment,
	})
	if err != nil {
		return fmt.Errorf("marshal servicenow comment payload: %w", err)
	}
	httpReq, err := http.NewRequest(http.MethodPatch, c.baseURL+"/api/now/v1/table/"+c.table+"/"+sysID, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build servicenow comment request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password)))
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("servicenow add comment: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("servicenow add comment returned %d", resp.StatusCode)
	}
	return nil
}

func extractServiceNowSysID(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	uri := parsed.Query().Get("uri")
	if uri == "" {
		return ""
	}
	index := strings.Index(uri, "sys_id=")
	if index < 0 {
		return ""
	}
	return strings.TrimSpace(uri[index+len("sys_id="):])
}
