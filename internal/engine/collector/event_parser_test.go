package collector

import (
	"encoding/binary"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

// makeRawEvent creates a 332-byte raw event buffer for testing.
// Fields are set via functional options; any nil field uses zero.
func makeRawEvent(t *testing.T, opts ...func([]byte)) []byte {
	t.Helper()
	buf := make([]byte, eventTotalSize)

	// Default: a basic file_open event
	le := binary.LittleEndian
	le.PutUint32(buf[0:4], uint32(syscall.EventFileOpen))
	le.PutUint32(buf[4:8], 0)          // flags
	le.PutUint64(buf[8:16], 1000000)   // timestamp
	le.PutUint32(buf[16:20], 1001)     // pid
	le.PutUint32(buf[20:24], 1001)     // tid
	le.PutUint32(buf[24:28], 1000)     // ppid
	le.PutUint32(buf[28:32], 1000)     // uid
	le.PutUint32(buf[32:36], 1000)     // gid
	// union payload (inode/dev/mode/f_flags)
	le.PutUint64(buf[36:44], 123456)   // inode
	le.PutUint32(buf[44:48], 8)        // dev_major
	le.PutUint32(buf[48:52], 3)        // dev_minor
	le.PutUint32(buf[52:56], 0o644)    // mode
	le.PutUint32(buf[56:60], 0)        // f_flags
	copy(buf[60:76], "test-prog\x00")  // comm
	copy(buf[76:], "/etc/passwd\x00")  // pathname

	for _, opt := range opts {
		opt(buf)
	}
	return buf
}

func TestParseRawEvent_FileOpen(t *testing.T) {
	data := makeRawEvent(t)
	evt, err := ParseRawEvent(data)
	if err != nil {
		t.Fatalf("ParseRawEvent: %v", err)
	}

	if evt.Type != syscall.EventFileOpen {
		t.Errorf("Type = %d, want %d", evt.Type, syscall.EventFileOpen)
	}
	if evt.PID != 1001 {
		t.Errorf("PID = %d, want 1001", evt.PID)
	}
	if evt.Inode != 123456 {
		t.Errorf("Inode = %d, want 123456", evt.Inode)
	}
	if evt.DevMajor != 8 {
		t.Errorf("DevMajor = %d, want 8", evt.DevMajor)
	}
	if evt.Mode != 0o644 {
		t.Errorf("Mode = %o, want 0644", evt.Mode)
	}
	if evt.Comm != "test-prog" {
		t.Errorf("Comm = %q, want %q", evt.Comm, "test-prog")
	}
	if evt.Pathname != "/etc/passwd" {
		t.Errorf("Pathname = %q, want %q", evt.Pathname, "/etc/passwd")
	}
}

func TestParseRawEvent_ProcessFork(t *testing.T) {
	data := makeRawEvent(t, func(buf []byte) {
		le := binary.LittleEndian
		le.PutUint32(buf[0:4], uint32(syscall.EventProcessFork))
		le.PutUint32(buf[36:40], 1002) // child_pid
		copy(buf[60:76], "sshd\x00")
		copy(buf[76:], "\x00") // empty pathname
	})

	evt, err := ParseRawEvent(data)
	if err != nil {
		t.Fatalf("ParseRawEvent: %v", err)
	}

	if evt.Type != syscall.EventProcessFork {
		t.Errorf("Type = %d", evt.Type)
	}
	if evt.ChildPID != 1002 {
		t.Errorf("ChildPID = %d, want 1002", evt.ChildPID)
	}
	if evt.Comm != "sshd" {
		t.Errorf("Comm = %q, want %q", evt.Comm, "sshd")
	}
	if evt.Pathname != "" {
		t.Errorf("Pathname = %q, want empty", evt.Pathname)
	}
}

func TestParseRawEvent_ProcessExec(t *testing.T) {
	data := makeRawEvent(t, func(buf []byte) {
		le := binary.LittleEndian
		le.PutUint32(buf[0:4], uint32(syscall.EventProcessExec))
		le.PutUint32(buf[4:8], uint32(syscall.EventFlagExecSetuid))
		copy(buf[60:76], "bash\x00")
		copy(buf[76:], "/usr/bin/bash\x00")
	})

	evt, err := ParseRawEvent(data)
	if err != nil {
		t.Fatalf("ParseRawEvent: %v", err)
	}

	if evt.Type != syscall.EventProcessExec {
		t.Errorf("Type = %d", evt.Type)
	}
	if evt.Flags != uint32(syscall.EventFlagExecSetuid) {
		t.Errorf("Flags = %d, want %d", evt.Flags, syscall.EventFlagExecSetuid)
	}
	if evt.Comm != "bash" {
		t.Errorf("Comm = %q", evt.Comm)
	}
	if evt.PPID != 1000 {
		t.Errorf("PPID = %d, want 1000", evt.PPID)
	}
}

func TestParseRawEvent_NetConnect(t *testing.T) {
	data := makeRawEvent(t, func(buf []byte) {
		le := binary.LittleEndian
		le.PutUint32(buf[0:4], uint32(syscall.EventNetConnect))
		copy(buf[60:76], "curl\x00")
		copy(buf[76:], "1.2.3.4:443\x00")
	})

	evt, err := ParseRawEvent(data)
	if err != nil {
		t.Fatalf("ParseRawEvent: %v", err)
	}

	if evt.Type != syscall.EventNetConnect {
		t.Errorf("Type = %d", evt.Type)
	}
	if evt.Comm != "curl" {
		t.Errorf("Comm = %q", evt.Comm)
	}
	if evt.Pathname != "1.2.3.4:443" {
		t.Errorf("Pathname = %q", evt.Pathname)
	}
}

func TestParseRawEvent_TooShort(t *testing.T) {
	_, err := ParseRawEvent([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short buffer")
	}
}

func TestParseRawEvent_AllEventTypes(t *testing.T) {
	types := []syscall.EventType{
		syscall.EventProcessFork, syscall.EventProcessExec, syscall.EventProcessExit,
		syscall.EventFileOpen, syscall.EventFileCreate, syscall.EventFileModify,
		syscall.EventFileDelete, syscall.EventFileRename,
		syscall.EventNetConnect, syscall.EventNetAccept, syscall.EventNetSend, syscall.EventNetRecv,
		syscall.EventCredSetuid, syscall.EventCredCapable,
		syscall.EventMemfdCreate, syscall.EventMprotectRX,
		syscall.EventPipeWrite, syscall.EventPipeRead,
	}

	for _, et := range types {
		data := makeRawEvent(t, func(buf []byte) {
			binary.LittleEndian.PutUint32(buf[0:4], uint32(et))
		})
		evt, err := ParseRawEvent(data)
		if err != nil {
			t.Fatalf("ParseRawEvent(%s): %v", et, err)
		}
		if evt.Type != et {
			t.Errorf("Type = %d, want %d", evt.Type, et)
		}
	}
}

func TestParseRawEvent_Timestamps(t *testing.T) {
	data := makeRawEvent(t)
	evt, err := ParseRawEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if evt.TimestampNS != 1000000 {
		t.Errorf("TimestampNS = %d, want 1000000", evt.TimestampNS)
	}
}

func TestParseRawEvent_ZeroFields(t *testing.T) {
	buf := make([]byte, eventTotalSize)
	// All zeros — should parse without error
	evt, err := ParseRawEvent(buf)
	if err != nil {
		t.Fatalf("ParseRawEvent(zeros): %v", err)
	}
	if evt.Type != 0 {
		t.Errorf("Type = %d, want 0", evt.Type)
	}
	if evt.Comm != "" {
		t.Errorf("Comm = %q, want empty", evt.Comm)
	}
	if evt.Pathname != "" {
		t.Errorf("Pathname = %q, want empty", evt.Pathname)
	}
}

func TestParseRawEvent_LongStrings(t *testing.T) {
	data := makeRawEvent(t, func(buf []byte) {
		// Fill comm with exactly 15 chars + null (max possible)
		copy(buf[60:76], "abcdefghijklmno\x00")
		// Fill pathname with exactly 255 chars + null
		path := make([]byte, 255)
		for i := range path {
			path[i] = 'a' + byte(i%26)
		}
		copy(buf[76:], append(path, 0))
	})

	evt, err := ParseRawEvent(data)
	if err != nil {
		t.Fatalf("ParseRawEvent: %v", err)
	}
	if evt.Comm != "abcdefghijklmno" {
		t.Errorf("Comm = %q", evt.Comm)
	}
	if len(evt.Pathname) != 255 {
		t.Errorf("Pathname length = %d, want 255", len(evt.Pathname))
	}
}

func TestParseRawEvent_ForkWithFilePayload(t *testing.T) {
	// A fork event with file union payload partially populated —
	// ensure the payload is always decoded regardless of event type.
	data := makeRawEvent(t, func(buf []byte) {
		le := binary.LittleEndian
		le.PutUint32(buf[0:4], uint32(syscall.EventProcessFork))
		le.PutUint32(buf[36:40], 1002) // child_pid
		// Also set file fields — these should still be decoded
		le.PutUint64(buf[36:44], 999)  // same offset as child_pid (overlap)!
	})

	evt, err := ParseRawEvent(data)
	if err != nil {
		t.Fatalf("ParseRawEvent: %v", err)
	}

	// Both ChildPID and Inode share offset 36 (union) —
	// last write wins in the binary encoding, but both are decoded.
	if evt.ChildPID != 999 {
		t.Errorf("ChildPID = %d, want 999 (last-written value at offset 36)", evt.ChildPID)
	}
	if evt.Inode != 999 {
		t.Errorf("Inode = %d, want 999", evt.Inode)
	}
}

func TestCString(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"null terminated", []byte("hello\x00world"), "hello"},
		{"no null", []byte("hello"), "hello"},
		{"empty", []byte{}, ""},
		{"all nulls", []byte{0, 0, 0}, ""},
		{"first char null", []byte{0, 'a', 'b'}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cString(tt.in)
			if got != tt.want {
				t.Errorf("cString(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// FuzzParseRawEvent fuzzes the raw event parser with arbitrary byte slices.
func FuzzParseRawEvent(f *testing.F) {
	f.Add([]byte{
		1, 0, 0, 0, // Type
		0, 0, 0, 0, // Flags
		0, 0, 0, 0, 0, 0, 0, 0, // Timestamp
		100, 0, 0, 0, // PID
		101, 0, 0, 0, // TID
		1, 0, 0, 0, // PPID
		232, 3, 0, 0, // UID = 1000
		0, 0, 0, 0, // GID
		0, 0, 0, 0, 0, 0, 0, 0, // Inode
		0, 0, 0, 0, // DevMajor
		0, 0, 0, 0, // DevMinor
		0, 0, 0, 0, // Mode
		0, 0, 0, 0, // FFlags
		0, 0, 0, 0, // ChildPID
		99, 0, // Comm (nul-terminated)
	})
	f.Fuzz(func(t *testing.T, data []byte) {
		evt, err := ParseRawEvent(data)
		_ = evt
		_ = err
	})
}

