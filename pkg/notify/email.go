// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"time"
)

// EmailNotifier sends alerts via SMTP email.
type EmailNotifier struct {
	smtpHost string
	smtpPort string
	username string
	password string
	fromAddr string
	toAddrs  []string
	useTLS   bool
}

// NewEmailNotifier creates a notifier that sends alerts via SMTP.
//
//	smtpAddr: "smtp.example.com:587"
//	username/password: SMTP auth credentials
//	fromAddr: sender address (e.g. "providapt@example.com")
//	toAddrs: recipient addresses
//
// Security: Port 587 uses STARTTLS (upgraded from plain); port 465
// uses direct TLS.  smtp.PlainAuth only transmits credentials after
// TLS is established, so password is never sent in cleartext.
func NewEmailNotifier(smtpAddr, username, password, fromAddr string, toAddrs []string) *EmailNotifier {
	host := smtpAddr
	port := "587"
	if parts := strings.SplitN(smtpAddr, ":", 2); len(parts) == 2 {
		host = parts[0]
		port = parts[1]
	}

	// Port 465 historically uses direct TLS; 587/25 use STARTTLS.
	useTLS := port == "465"

	return &EmailNotifier{
		smtpHost: host,
		smtpPort: port,
		username: username,
		password: password,
		fromAddr: fromAddr,
		toAddrs:  toAddrs,
		useTLS:   useTLS,
	}
}

// Name returns the notifier identifier.
func (e *EmailNotifier) Name() string {
	if len(e.toAddrs) > 0 {
		return fmt.Sprintf("email:%s", e.toAddrs[0])
	}
	return "email"
}

// Send delivers the alert via SMTP email.
func (e *EmailNotifier) Send(alert Alert) error {
	if len(e.toAddrs) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	subject := fmt.Sprintf("[ProvidAPT] [%s] %s", alert.Severity, alert.Pattern)
	body := fmt.Sprintf(`From: %s
To: %s
Subject: %s
Date: %s
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

ProvidAPT Alert
===============
Severity: %s
Pattern:  %s
Time:     %s

%s
`,
		e.fromAddr,
		strings.Join(e.toAddrs, ", "),
		subject,
		alert.Timestamp.Format(time.RFC1123Z),
		alert.Severity,
		alert.Pattern,
		alert.Timestamp.Format(time.RFC3339),
		alert.Headline,
	)

	if alert.Reason != "" {
		body += fmt.Sprintf("\nDetails:\n%s\n", alert.Reason)
	}
	if len(alert.Details) > 0 {
		body += "\nMetadata:\n"
		for k, v := range alert.Details {
			body += fmt.Sprintf("  %s: %s\n", k, v)
		}
	}

	addr := fmt.Sprintf("%s:%s", e.smtpHost, e.smtpPort)

	if e.useTLS {
		// Direct TLS (port 465) — dial encrypted connection first
		tlsCfg := &tls.Config{
			ServerName: e.smtpHost,
			MinVersion: tls.VersionTLS12,
		}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("tls dial: %w", err)
		}
		client, err := smtp.NewClient(conn, e.smtpHost)
		if err != nil {
			conn.Close()
			return fmt.Errorf("smtp client: %w", err)
		}
		defer client.Close()

		auth := smtp.PlainAuth("", e.username, e.password, e.smtpHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
		if err := client.Mail(e.fromAddr); err != nil {
			return fmt.Errorf("smtp mail from: %w", err)
		}
		for _, addr := range e.toAddrs {
			if err := client.Rcpt(addr); err != nil {
				return fmt.Errorf("smtp rcpt %s: %w", addr, err)
			}
		}
		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("smtp data: %w", err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			return fmt.Errorf("smtp write: %w", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("smtp close: %w", err)
		}
		return client.Quit()
	}

	// STARTTLS (port 587) — smtp.SendMail handles STARTTLS negotiation.
	// PlainAuth only transmits credentials after TLS is established.
	auth := smtp.PlainAuth("", e.username, e.password, e.smtpHost)
	msg := []byte(body)
	if err := smtp.SendMail(addr, auth, e.fromAddr, e.toAddrs, msg); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}
