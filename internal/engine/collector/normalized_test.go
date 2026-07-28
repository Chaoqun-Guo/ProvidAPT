package collector

import (
	"encoding/json"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

func TestNormalizeEventForkTypedPayload(t *testing.T) {
	evt := &Event{
		Type:        syscall.EventProcessFork,
		TimestampNS: 1000,
		PID:         10,
		TID:         10,
		PPID:        1,
		UID:         0,
		GID:         0,
		Comm:        "bash",
		ChildPID:    11,
		Inode:       11,
		Saddr:       11,
	}

	normalized := NormalizeEvent(evt)
	if normalized.Type != "proc_fork" || normalized.TypeID != 1 {
		t.Fatalf("type = %s/%d, want proc_fork/1", normalized.Type, normalized.TypeID)
	}
	if normalized.Raw.PayloadKind != "fork" {
		t.Fatalf("payload kind = %q, want fork", normalized.Raw.PayloadKind)
	}
	if normalized.Payload["child_pid"] != uint32(11) {
		t.Fatalf("child_pid = %#v, want 11", normalized.Payload["child_pid"])
	}
	if _, ok := normalized.Payload["inode"]; ok {
		t.Fatal("fork payload should not include inode")
	}
	if _, ok := normalized.Payload["saddr"]; ok {
		t.Fatal("fork payload should not include saddr")
	}
}

func TestParseStoredEventJSONSupportsNormalized(t *testing.T) {
	normalized := NormalizeEvent(&Event{
		Type:          syscall.EventFileModify,
		TimestampNS:   1000,
		PID:           10,
		UID:           1000,
		Comm:          "curl",
		Pathname:      "/tmp/payload.sh",
		Inode:         123,
		DevMajor:      8,
		DevMinor:      3,
		FFlags:        1,
		ExePath:       "/usr/bin/curl",
		Cmdline:       "curl -o /tmp/payload.sh https://example.com",
		CmdlineSource: "procfs",
		Cwd:           "/tmp",
	})
	data, err := json.Marshal(normalized)
	if err != nil {
		t.Fatalf("marshal normalized: %v", err)
	}

	evt, err := ParseStoredEventJSON(data)
	if err != nil {
		t.Fatalf("ParseStoredEventJSON: %v", err)
	}
	if evt.Type != syscall.EventFileModify || evt.Pathname != "/tmp/payload.sh" || evt.Inode != 123 {
		t.Fatalf("parsed event = %#v", evt)
	}
	if evt.ExePath != "/usr/bin/curl" || evt.Cmdline == "" || evt.CmdlineSource != "procfs" || evt.Cwd != "/tmp" {
		t.Fatalf("enrich fields not preserved: %#v", evt)
	}
}

func TestParseStoredEventJSONSupportsLegacy(t *testing.T) {
	data := []byte(`{"Type":1,"PID":10,"Comm":"bash","ChildPID":11}`)
	evt, err := ParseStoredEventJSON(data)
	if err != nil {
		t.Fatalf("ParseStoredEventJSON legacy: %v", err)
	}
	if evt.Type != syscall.EventProcessFork || evt.ChildPID != 11 {
		t.Fatalf("legacy event = %#v", evt)
	}
}
