package collector

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Enrich adds cross-referenced metadata to a raw event.
// Currently resolves UID→username and binary path from /proc/<pid>/exe.
// Enrichment results are stored in the Event's Comm and Pathname fields
// (Comm is updated to include the username, Pathname resolves the binary).
func (e *Event) Enrich() {
	// Resolve UID to username
	if e.UID != 0 {
		if u, err := user.LookupId(strconv.Itoa(int(e.UID))); err == nil {
			e.Comm = fmt.Sprintf("%s[%s]", e.Comm, u.Username)
		}
	}

	// Resolve binary path from /proc/<pid>/exe (Linux only)
	if e.PID > 0 {
		exePath := filepath.Join("/proc", strconv.Itoa(int(e.PID)), "exe")
		if target, err := os.Readlink(exePath); err == nil && target != "" {
			if !strings.Contains(e.Pathname, target) {
				if e.Pathname != "" {
					e.Pathname = target + " (" + e.Pathname + ")"
				} else {
					e.Pathname = target
				}
			}
		}
	}
}
