// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ticketing

import "time"

type CreateRequest struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity,omitempty"`
	Labels      []string          `json:"labels,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type Issue struct {
	Provider  string    `json:"provider"`
	Key       string    `json:"key,omitempty"`
	URL       string    `json:"url,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Client interface {
	Provider() string
	CreateIssue(req CreateRequest) (Issue, error)
	AddComment(issue Issue, comment string) error
}
