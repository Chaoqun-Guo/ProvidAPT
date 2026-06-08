// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/logx"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/ticketing"
)

func initTicketClient(cfg *config.Config) ticketing.Client {
	switch strings.ToLower(strings.TrimSpace(cfg.Notify.TicketProvider)) {
	case "webhook":
		if cfg.Notify.TicketWebhookURL == "" {
			return nil
		}
		client := ticketing.NewWebhookClient(cfg.Notify.TicketWebhookURL, cfg.Notify.TicketWebhookAuth)
		logx.System().Info("ticketing enabled", "provider", client.Provider())
		return client
	case "jira":
		client := ticketing.NewJiraClient(
			cfg.Notify.JiraBaseURL,
			cfg.Notify.JiraEmail,
			cfg.Notify.JiraAPIToken,
			cfg.Notify.JiraProjectKey,
			cfg.Notify.JiraIssueType,
		)
		logx.System().Info("ticketing enabled", "provider", client.Provider(), "project", cfg.Notify.JiraProjectKey)
		return client
	case "servicenow":
		client := ticketing.NewServiceNowClient(
			cfg.Notify.ServiceNowBaseURL,
			cfg.Notify.ServiceNowUser,
			cfg.Notify.ServiceNowPass,
			cfg.Notify.ServiceNowTable,
		)
		logx.System().Info("ticketing enabled", "provider", client.Provider(), "table", cfg.Notify.ServiceNowTable)
		return client
	default:
		return nil
	}
}
