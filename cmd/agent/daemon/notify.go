// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/logx"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/notify"
)

// initNotifier builds a notification Manager from the daemon config.
// Returns nil when no notification channels are configured.
func initNotifier(cfg *config.Config) *notify.Manager {
	nc := cfg.Notify
	if nc.SlackWebhook == "" && nc.SMTPAddr == "" && nc.WebhookURL == "" {
		return nil
	}

	mgr := notify.NewManager()

	// Configure throttling
	if nc.MinInterval != "" {
		d, err := time.ParseDuration(nc.MinInterval)
		if err == nil && d > 0 {
			mgr.SetMinInterval(d)
			logx.System().Info("notify throttle interval", "interval", d)
		}
	}
	if nc.MaxAttempts > 0 || nc.RetryBackoff != "" {
		maxAttempts := nc.MaxAttempts
		if maxAttempts <= 0 {
			maxAttempts = 3
		}
		retryBackoff := 250 * time.Millisecond
		if nc.RetryBackoff != "" {
			if d, err := time.ParseDuration(nc.RetryBackoff); err == nil && d >= 0 {
				retryBackoff = d
			}
		}
		mgr.SetRetryPolicy(maxAttempts, retryBackoff)
		logx.System().Info("notify retry policy", "max_attempts", maxAttempts, "backoff", retryBackoff)
	}

	// Slack
	if nc.SlackWebhook != "" {
		slack := notify.NewSlackNotifier(nc.SlackWebhook)
		if nc.SlackChannel != "" {
			slack.SetChannel(nc.SlackChannel)
		}
		mgr.AddNotifier(slack)
		logx.System().Info("notify: slack enabled", "channel", nc.SlackChannel)
	}

	// Email (SMTP)
	if nc.SMTPAddr != "" {
		email := notify.NewEmailNotifier(nc.SMTPAddr, nc.SMTPUser, nc.SMTPPass, nc.EmailFrom, nc.EmailTo)
		mgr.AddNotifier(email)
		logx.System().Info("notify: email enabled", "to", nc.EmailTo)
	}

	// Generic webhook
	if nc.WebhookURL != "" {
		wh := notify.NewWebhookNotifier(nc.WebhookURL)
		if nc.WebhookSecret != "" {
			wh.SetSecret(nc.WebhookSecret)
		}
		mgr.AddNotifier(wh)
		logx.System().Info("notify: webhook enabled", "url", nc.WebhookURL)
	}

	return mgr
}
