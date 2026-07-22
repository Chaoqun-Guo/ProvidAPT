// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

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
// Currently resolves UID to username and binary path from /proc/<pid>/exe.
// Pathname remains the kernel-reported target path; ExePath stores the
// process executable path.
func (e *Event) Enrich() {
	if e.UID != 0 {
		if u, err := user.LookupId(strconv.Itoa(int(e.UID))); err == nil {
			e.Comm = fmt.Sprintf("%s[%s]", e.Comm, u.Username)
		}
	}

	if e.PID > 0 {
		exePath := filepath.Join("/proc", strconv.Itoa(int(e.PID)), "exe")
		if target, err := os.Readlink(exePath); err == nil && target != "" {
			e.ExePath = target
		}
		cmdlinePath := filepath.Join("/proc", strconv.Itoa(int(e.PID)), "cmdline")
		if data, err := os.ReadFile(cmdlinePath); err == nil {
			cmdline := strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
			e.Cmdline = strings.TrimSpace(cmdline)
		}
	}
}
