// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package secure

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

const (
	ProvidaptUser = "providapt"
	ProvidaptUID  = 950
	ProvidaptGID  = 950
)

func providaptIDs() (int, int, error) {
	u, err := user.Lookup(ProvidaptUser)
	if err != nil {
		return ProvidaptUID, ProvidaptGID, fmt.Errorf("lookup user %s: %w", ProvidaptUser, err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return ProvidaptUID, ProvidaptGID, fmt.Errorf("parse uid %s: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return ProvidaptUID, ProvidaptGID, fmt.Errorf("parse gid %s: %w", u.Gid, err)
	}

	return uid, gid, nil
}

// DropPrivileges drops from root to the providapt user.
// Must be called AFTER eBPF programs are loaded and maps are pinned.
func DropPrivileges() error {
	if !IsPrivileged() {
		return nil // not running as root, nothing to do
	}

	u, err := user.Lookup(ProvidaptUser)
	if err != nil {
		return fmt.Errorf("lookup user %s: %w", ProvidaptUser, err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parse uid %s: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("parse gid %s: %w", u.Gid, err)
	}

	// Set supplementary groups
	groupIDs, err := u.GroupIds()
	if err == nil {
		gids := make([]int, len(groupIDs))
		for i, g := range groupIDs {
			gids[i], err = strconv.Atoi(g)
			if err != nil {
				return fmt.Errorf("parse gid %q: %w", g, err)
			}
		}
		syscall.Setgroups(gids)
	}

	// Drop credentials
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid %d: %w", uid, err)
	}

	// Verify
	if syscall.Getuid() != uid {
		return fmt.Errorf("privilege drop verification failed: uid=%d, expected=%d", syscall.Getuid(), uid)
	}

	return nil
}

// IsPrivileged returns true if running as root (UID 0).
func IsPrivileged() bool {
	return syscall.Getuid() == 0
}

// EnsureDataDirOwnership sets the ownership of path to providapt:providapt.
// Only effective when running as root.
func EnsureDataDirOwnership(path string) error {
	uid, gid, err := providaptIDs()
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}
