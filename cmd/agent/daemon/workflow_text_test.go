// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/alertflow"
)

func TestToAPIAlertWorkflowItemCleansMojibake(t *testing.T) {
	arrow := mojibakeToken(0x922b, "?")
	dash := mojibakeToken(0x9225, "?")
	item := alertflow.Alert{
		ID:       "alert-1",
		Severity: "medium",
		Pattern:  "DEEP_TAINT_CHAIN",
		Headline: "apache " + arrow + "bash " + arrow + "curl",
		Reason:   "path " + dash + "decoded",
		Source:   "agent-1",
		Status:   alertflow.StatusOpen,
		Count:    1,
		Details: map[string]string{
			"chain" + arrow + "path": "a " + arrow + " b",
		},
	}

	out := toAPIAlertWorkflowItem(item)
	combined := out.Headline + out.Reason + out.Details["chain->path"]
	if strings.Contains(combined, arrow) || strings.Contains(combined, dash) {
		t.Fatalf("workflow text still contains mojibake: %#v", out)
	}
	if out.Headline != "apache -> bash -> curl" {
		t.Fatalf("headline = %q", out.Headline)
	}
}
