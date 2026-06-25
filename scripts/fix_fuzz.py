#!/usr/bin/env python3
"""Fix broken fuzz targets in test files."""

import re

# Fix forensic
with open('internal/engine/forensic/forensic_test.go', 'r') as f:
    content = f.read()
# Remove all FuzzHashHex functions
while 'FuzzHashHex' in content:
    content = re.sub(r'\nfunc FuzzHashHex\(f \*testing\.F\)[^}]*\n}\n', '\n', content, count=1)
with open('internal/engine/forensic/forensic_test.go', 'w') as f:
    f.write(content)
    f.write("""
// FuzzHashHex fuzzes HashHex with arbitrary binary data.
func FuzzHashHex(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add([]byte("the quick brown fox"))
	f.Fuzz(func(t *testing.T, data []byte) {
		result := HashHex(data)
		if len(result) == 0 {
			t.Error("HashHex returned empty")
		}
	})
}
""")
print('forensic ok')

# Fix anonymize
with open('pkg/anonymize/anonymize_test.go', 'r') as f:
    content = f.read()
while 'FuzzAnonymizeHashString' in content:
    content = re.sub(r'\nfunc FuzzAnonymizeHashString\(f \*testing\.F\)[^}]*\n}\n', '\n', content, count=1)
with open('pkg/anonymize/anonymize_test.go', 'w') as f:
    f.write(content)
    f.write("""
// FuzzAnonymizeHashString fuzzes HashString and related hash functions.
func FuzzAnonymizeHashString(f *testing.F) {
	f.Add("hello")
	f.Add("/etc/shadow")
	f.Add("192.168.1.1")
	f.Add("")
	f.Add("invalid")
	f.Fuzz(func(t *testing.T, input string) {
		a, err := New(nil)
		if err != nil {
			return
		}
		_ = a.HashString(input, 0)
		_ = a.HashString(input, 8)
		_ = a.HashPath(input)
		_ = a.HashIP(input)
		_ = a.HashComm(input)
		_ = IsAnonymizedPath(input)
	})
}
""")
print('anonymize ok')

# Fix syscall
with open('internal/engine/syscall/syscall_test.go', 'r') as f:
    content = f.read()
while 'FuzzEventTypeString' in content:
    content = re.sub(r'\nfunc FuzzEventTypeString\(f \*testing\.F\)[^}]*\n}\n', '\n', content, count=1)
while 'EventTypeName' in content:
    content = content.replace('_ = EventTypeName(name)', '')
    content = content.replace('EventTypeName(name)', '')
with open('internal/engine/syscall/syscall_test.go', 'w') as f:
    f.write(content)
    f.write("""
// FuzzEventTypeString fuzzes EventType.String() with arbitrary values.
func FuzzEventTypeString(f *testing.F) {
	f.Add(EventType(0))
	f.Add(EventType(100))
	f.Add(EventType(255))
	f.Fuzz(func(t *testing.T, et EventType) {
		s := et.String()
		if s == "" {
			t.Errorf("String() returned empty for %d", et)
		}
	})
}
""")
print('syscall ok')
