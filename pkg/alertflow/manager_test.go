// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package alertflow

import (
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/notify"
)

func TestIngestDedup(t *testing.T) {
	mgr := NewManager()
	mgr.SetDedupWindow(time.Hour)

	first, deliver := mgr.Ingest(notify.Alert{
		Pattern:   "SIGMA_SHADOW",
		Severity:  notify.SeverityHigh,
		Headline:  "shadow read",
		Source:    "analyzer",
		Timestamp: time.Now().UTC(),
	})
	if !deliver {
		t.Fatal("first alert should notify")
	}
	second, deliver := mgr.Ingest(notify.Alert{
		Pattern:   "SIGMA_SHADOW",
		Severity:  notify.SeverityHigh,
		Headline:  "shadow read",
		Source:    "analyzer",
		Timestamp: time.Now().UTC().Add(5 * time.Minute),
	})
	if deliver {
		t.Fatal("deduped alert should be suppressed")
	}
	if first.ID != second.ID {
		t.Fatalf("expected same alert id, got %q and %q", first.ID, second.ID)
	}
	if second.Count != 2 {
		t.Fatalf("count = %d, want 2", second.Count)
	}
}

func TestSilenceAndUnsilence(t *testing.T) {
	mgr := NewManager()
	record, _ := mgr.Ingest(notify.Alert{
		ID:        "a-1",
		Pattern:   "P1",
		Severity:  notify.SeverityMedium,
		Headline:  "test",
		Timestamp: time.Now().UTC(),
	})
	updated, err := mgr.Update(UpdateRequest{
		Action:   "silence",
		AlertID:  record.ID,
		Duration: "1h",
	})
	if err != nil {
		t.Fatalf("silence failed: %v", err)
	}
	if updated.Status != StatusSuppressed {
		t.Fatalf("status = %s, want suppressed", updated.Status)
	}
	updated, err = mgr.Update(UpdateRequest{
		Action:  "unsilence",
		AlertID: record.ID,
	})
	if err != nil {
		t.Fatalf("unsilence failed: %v", err)
	}
	if updated.Status != StatusOpen {
		t.Fatalf("status = %s, want open", updated.Status)
	}
}

func TestAssignAndClose(t *testing.T) {
	mgr := NewManager()
	record, _ := mgr.Ingest(notify.Alert{
		ID:        "a-2",
		Pattern:   "P2",
		Severity:  notify.SeverityCritical,
		Headline:  "critical",
		Timestamp: time.Now().UTC(),
	})
	updated, err := mgr.Update(UpdateRequest{
		Action:   "assign",
		AlertID:  record.ID,
		Assignee: "alice",
	})
	if err != nil {
		t.Fatalf("assign failed: %v", err)
	}
	if updated.Status != StatusAssigned {
		t.Fatalf("status = %s, want assigned", updated.Status)
	}
	if updated.Assignee != "alice" {
		t.Fatalf("assignee = %q", updated.Assignee)
	}
	updated, err = mgr.Update(UpdateRequest{
		Action:  "close",
		AlertID: record.ID,
	})
	if err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if updated.Status != StatusClosed {
		t.Fatalf("status = %s, want closed", updated.Status)
	}
}
