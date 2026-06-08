// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type JiraClient struct {
	baseURL    string
	email      string
	apiToken   string
	projectKey string
	issueType  string
	client     *http.Client
}

func NewJiraClient(baseURL, email, apiToken, projectKey, issueType string) *JiraClient {
	if strings.TrimSpace(issueType) == "" {
		issueType = "Task"
	}
	return &JiraClient{
		baseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		email:      strings.TrimSpace(email),
		apiToken:   strings.TrimSpace(apiToken),
		projectKey: strings.TrimSpace(projectKey),
		issueType:  issueType,
		client:     &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *JiraClient) Provider() string { return "jira" }

type jiraIssuePayload struct {
	Fields jiraIssueFields `json:"fields"`
}

type jiraIssueFields struct {
	Project     jiraProject   `json:"project"`
	IssueType   jiraIssueType `json:"issuetype"`
	Summary     string        `json:"summary"`
	Description string        `json:"description"`
	Labels      []string      `json:"labels,omitempty"`
	Priority    *jiraPriority `json:"priority,omitempty"`
}

type jiraProject struct {
	Key string `json:"key"`
}

type jiraIssueType struct {
	Name string `json:"name"`
}

type jiraPriority struct {
	Name string `json:"name"`
}

type jiraCreateResponse struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Self string `json:"self"`
}

type jiraCommentPayload struct {
	Body string `json:"body"`
}

func (c *JiraClient) CreateIssue(req CreateRequest) (Issue, error) {
	if c.baseURL == "" || c.email == "" || c.apiToken == "" || c.projectKey == "" {
		return Issue{}, fmt.Errorf("jira client is not fully configured")
	}

	payload := jiraIssuePayload{
		Fields: jiraIssueFields{
			Project:     jiraProject{Key: c.projectKey},
			IssueType:   jiraIssueType{Name: c.issueType},
			Summary:     req.Title,
			Description: req.Description,
			Labels:      req.Labels,
		},
	}
	if priority := jiraPriorityForSeverity(req.Severity); priority != "" {
		payload.Fields.Priority = &jiraPriority{Name: priority}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return Issue{}, fmt.Errorf("marshal jira issue payload: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.baseURL+"/rest/api/3/issue", bytes.NewReader(body))
	if err != nil {
		return Issue{}, fmt.Errorf("build jira request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.email+":"+c.apiToken)))

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return Issue{}, fmt.Errorf("jira create issue: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return Issue{}, fmt.Errorf("jira create issue returned %d", resp.StatusCode)
	}

	var created jiraCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return Issue{}, fmt.Errorf("decode jira create response: %w", err)
	}

	url := strings.TrimRight(c.baseURL, "/")
	if created.Key != "" {
		url += "/browse/" + created.Key
	}
	return Issue{
		Provider:  c.Provider(),
		Key:       created.Key,
		URL:       url,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (c *JiraClient) AddComment(issue Issue, comment string) error {
	if c.baseURL == "" || c.email == "" || c.apiToken == "" {
		return fmt.Errorf("jira client is not fully configured")
	}
	issueKey := strings.TrimSpace(issue.Key)
	if issueKey == "" {
		return fmt.Errorf("jira issue key is required for comments")
	}
	payload, err := json.Marshal(jiraCommentPayload{Body: comment})
	if err != nil {
		return fmt.Errorf("marshal jira comment payload: %w", err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, c.baseURL+"/rest/api/3/issue/"+issueKey+"/comment", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build jira comment request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.email+":"+c.apiToken)))
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("jira add comment: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("jira add comment returned %d", resp.StatusCode)
	}
	return nil
}

func jiraPriorityForSeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "Highest"
	case "HIGH":
		return "High"
	case "MEDIUM":
		return "Medium"
	case "LOW":
		return "Low"
	default:
		return ""
	}
}
