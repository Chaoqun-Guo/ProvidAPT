package benchmark

import (
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/internal/syscall"
)

const eventSize = 332

// makeTestEvent creates a properly-sized ring buffer record for testing.
func makeTestEvent(eventType byte) []byte {
	raw := make([]byte, eventSize)
	raw[0] = eventType       // type at offset 0
	raw[4] = 0               // flags at offset 4
	raw[16] = 42             // pid (LSB) at offset 16
	raw[28] = 1000           // uid (LSB) at offset 28
	raw[60] = 't'            // comm[0] at offset 60
	raw[61] = 'e'
	raw[62] = 's'
	raw[63] = 't'
	raw[64] = 0              // NUL terminator
	raw[76] = '/'            // pathname[0] at offset 76
	raw[77] = 'e'
	raw[78] = 't'
	raw[79] = 'c'
	raw[80] = '/'
	raw[81] = 'h'
	raw[82] = 'o'
	raw[83] = 's'
	raw[84] = 't'
	raw[85] = 'n'
	raw[86] = 'a'
	raw[87] = 'm'
	raw[88] = 'e'
	raw[89] = 0              // NUL terminator
	return raw
}

// BenchmarkEventParsing measures the overhead of decoding ring buffer events.
func BenchmarkEventParsing(b *testing.B) {
	raw := makeTestEvent(byte(syscall.EventFileOpen))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := collector.ParseRawEvent(raw)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/sec")
}

// BenchmarkEventParsingParallel measures throughput under concurrent access.
func BenchmarkEventParsingParallel(b *testing.B) {
	raw := makeTestEvent(byte(syscall.EventFileOpen))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := collector.ParseRawEvent(raw)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestEventTypes(t *testing.T) {
	tests := []struct {
		rawType byte
		want    string
	}{
		{byte(syscall.EventProcessFork), "proc_fork"},
		{byte(syscall.EventProcessExec), "proc_exec"},
		{byte(syscall.EventFileOpen), "file_open"},
		{byte(syscall.EventFileCreate), "file_create"},
		{byte(syscall.EventFileModify), "file_modify"},
		{byte(syscall.EventFileDelete), "file_delete"},
		{byte(syscall.EventNetConnect), "net_connect"},
		{byte(syscall.EventCredSetuid), "cred_setuid"},
	}
	for _, tt := range tests {
		raw := makeTestEvent(tt.rawType)
		evt, err := collector.ParseRawEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		if evt.Type.String() != tt.want {
			t.Errorf("type %d: got %q, want %q", tt.rawType, evt.Type.String(), tt.want)
		}
	}
}

func TestParseFileOpen(t *testing.T) {
	raw := makeTestEvent(byte(syscall.EventFileOpen))
	evt, err := collector.ParseRawEvent(raw)
	if err != nil {
		t.Fatal(err)
	}

	if evt.PID != 42 {
		t.Errorf("PID = %d, want 42", evt.PID)
	}
	if evt.Comm != "test" {
		t.Errorf("Comm = %q, want %q", evt.Comm, "test")
	}
	if evt.Pathname != "/etc/hostname" {
		t.Errorf("Pathname = %q, want %q", evt.Pathname, "/etc/hostname")
	}
	if evt.Type != syscall.EventFileOpen {
		t.Errorf("Type = %d, want %d", evt.Type, syscall.EventFileOpen)
	}
}

func TestParseUnderflow(t *testing.T) {
	_, err := collector.ParseRawEvent(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short buffer")
	}
}

func TestCaptureMetrics(t *testing.T) {
	events := 10000
	start := time.Now()

	for i := 0; i < events; i++ {
		raw := makeTestEvent(byte(i%7 + 1)) // cycle through valid types 1-7
		_, err := collector.ParseRawEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
	}

	elapsed := time.Since(start)
	t.Logf("parsed %d events in %v (%.0f events/sec)",
		events, elapsed, float64(events)/elapsed.Seconds())
}
