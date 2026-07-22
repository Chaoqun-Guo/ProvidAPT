package api

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSearchEventsReadsNormalizedRecords(t *testing.T) {
	dir := t.TempDir()
	record := `{"schema_version":1,"type":"file_write","timestamp_ns":1700000000000000000,"process":{"pid":4242,"comm":"curl","exe_path":"/usr/bin/curl"},"payload":{"kind":"file","pathname":"/tmp/payload.sh","inode":123},"raw":{"payload_kind":"file"}}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "providapt-20260722T010000Z.ndjson"), []byte(record), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	results, err := searchEvents(dir, SearchParams{Pattern: "payload.sh", Limit: 10})
	if err != nil {
		t.Fatalf("searchEvents: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	got := results[0]
	if got.PID != 4242 || got.Comm != "curl" || got.Type != "file_write" {
		t.Fatalf("record = %#v", got)
	}
	if got.Label != "/tmp/payload.sh" {
		t.Fatalf("label = %q", got.Label)
	}
	if got.Timestamp == "" {
		t.Fatal("timestamp should be populated")
	}
}

func TestSearchEventsIncludesAlertsButRecentDoesNot(t *testing.T) {
	dir := t.TempDir()
	eventRecord := `{"schema_version":1,"type":"process_exec","timestamp_ns":1700000000000000000,"process":{"pid":100,"comm":"bash"},"payload":{"kind":"process","exe_path":"/usr/bin/bash"}}` + "\n"
	alertRecord := `{"timestamp":"2026-07-22T01:00:00Z","rule_id":"curl-download","severity":"HIGH","message":"curl downloaded a payload","comm":"curl","pid":200}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "providapt-20260722T010000Z.ndjson"), []byte(eventRecord), 0644); err != nil {
		t.Fatalf("write event: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "alerts.ndjson"), []byte(alertRecord), 0644); err != nil {
		t.Fatalf("write alert: %v", err)
	}

	results, err := searchEvents(dir, SearchParams{Pattern: "curl-download", Limit: 10})
	if err != nil {
		t.Fatalf("searchEvents: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("alert results = %d, want 1", len(results))
	}
	if results[0].Type != "alert" || results[0].Comm != "curl" || results[0].Label != "curl downloaded a payload" {
		t.Fatalf("alert record = %#v", results[0])
	}

	recent, err := recentEvents(dir, 10)
	if err != nil {
		t.Fatalf("recentEvents: %v", err)
	}
	if len(recent) != 1 || recent[0].Type != "process_exec" {
		t.Fatalf("recent = %#v, want event-only recent list", recent)
	}
}
