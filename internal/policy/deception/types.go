// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package deception implements active defense through honeytoken
// deception. It injects phantom sensitive files into directory
// listings (via overlayfs mounts), monitors for access to these
// files via eBPF, and freezes triggering processes via CGroups.
package deception

import "time"

// ─────────────────────────────────────────────────────────────────
// Honeytoken definitions
// ─────────────────────────────────────────────────────────────────

// HoneytokenType classifies the kind of honeytoken.
type HoneytokenType string

const (
	HoneytokenCredentials HoneytokenType = "credentials" // backup_credentials.xml
	HoneytokenBackup      HoneytokenType = "backup"      // db_backup.sql
	HoneytokenConfig      HoneytokenType = "config"      // config.json with secrets
	HoneytokenKey         HoneytokenType = "key"         // private SSH key
	HoneytokenKubeconfig  HoneytokenType = "kubeconfig"  // k8s admin config
	HoneytokenVault       HoneytokenType = "vault"       // vault token file
)
// Honeytoken eBPF map flags — mirrors cmd/bpf/headers/deception.h.
const (
	HONEYPOT_ACTIVE    = 1 << 0 // honeytoken injection active
	HONEYPOT_TRIGGERED = 1 << 1 // honeytoken was accessed
	HONEYPOT_TRIPWIRE  = 1 << 2 // file is a tripwire (immediate freeze)
)


// HoneytokenDef describes a single honeytoken file to inject.
type HoneytokenDef struct {
	// Path is the full path where the honeytoken appears (e.g.,
	// "/tmp/backup_credentials.xml"). The file does not exist on
	// the real filesystem — it is injected via overlay mount.
	Path string `json:"path"`

	// Type classifies the honeytoken for alerting purposes.
	Type HoneytokenType `json:"type"`

	// Label is a human-readable description.
	Label string `json:"label"`

	// Content is the fake file content shown when the file is read.
	Content string `json:"content,omitempty"`

	// Tripwire, when true, immediately freezes any process that
	// touches this file (no further analysis needed).
	Tripwire bool `json:"tripwire"`
}

// ─────────────────────────────────────────────────────────────────
// Trigger event
// ─────────────────────────────────────────────────────────────────

// TriggerType describes how a honeytoken was triggered.
type TriggerType string

const (
	TrigOpen     TriggerType = "open"      // open/creat syscall
	TrigStat     TriggerType = "stat"      // stat/statx/lstat
	TrigGetdents TriggerType = "getdents"  // directory listing
	TrigReadlink TriggerType = "readlink"  // readlink
)

// HoneypotTrigger is emitted when a process accesses a honeytoken.
type HoneypotTrigger struct {
	// Process info.
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid,omitempty"`
	UID  uint32 `json:"uid,omitempty"`
	Comm string `json:"comm"`

	// Honeytoken info.
	Path       string         `json:"path"`
	PathHash   uint32         `json:"path_hash"`
	TokenType  HoneytokenType `json:"token_type"`
	Trigger    TriggerType    `json:"trigger"`

	// Risk assessment.
	Tripwire bool `json:"tripwire"`

	// Timing.
	Timestamp time.Time `json:"timestamp"`
}

// ─────────────────────────────────────────────────────────────────
// Freeze state
// ─────────────────────────────────────────────────────────────────

// FreezeState tracks the state of a frozen process.
type FreezeState string

const (
	FreezePending    FreezeState = "pending"     // freeze requested
	FreezeCGroupSet  FreezeState = "cgroup_set"  // cgroup cpu limit applied
	FreezeComplete   FreezeState = "complete"    // all freeze actions done
	FreezeReleased   FreezeState = "released"    // process released by operator
	FreezeFailed     FreezeState = "failed"      // freeze operation failed
)

// ProcessContext captures the forensic context of a frozen process.
type ProcessContext struct {
	PID        int               `json:"pid"`
	Comm       string            `json:"comm"`
	Cmdline    string            `json:"cmdline"`
	EnvVars    map[string]string `json:"env_vars,omitempty"`
	MmapRegions []string         `json:"mmap_regions,omitempty"`
	OpenFDs    []string          `json:"open_fds,omitempty"`
	Status     string            `json:"status,omitempty"`
	Seccomp    string            `json:"seccomp,omitempty"`
	CGroupPath string            `json:"cgroup_path,omitempty"`
	CapturedAt time.Time         `json:"captured_at"`
}

// FreezeRecord is the persistent record of a freeze operation.
type FreezeRecord struct {
	PID          int             `json:"pid"`
	Comm         string          `json:"comm"`
	Trigger      HoneypotTrigger `json:"trigger"`
	State        FreezeState     `json:"state"`
	Context      ProcessContext  `json:"context,omitempty"`
	CGroupsPath string          `json:"cgroups_path,omitempty"`
	FrozenAt    time.Time       `json:"frozen_at"`
	ReleasedAt  *time.Time      `json:"released_at,omitempty"`
}

// ─────────────────────────────────────────────────────────────────
// Overlay mount state
// ─────────────────────────────────────────────────────────────────

// OverlayMount describes an active overlayfs mount for honeytoken injection.
type OverlayMount struct {
	TargetDir string `json:"target_dir"`  // directory being overlaid
	UpperDir  string `json:"upper_dir"`   // temp dir with honeytoken files
	WorkDir   string `json:"work_dir"`    // overlay work dir
	MountedAt string `json:"mounted_at"`  // mount point (same as target)
	Created   time.Time `json:"created"`
}

// ─────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────

// Config configures the deception module.
type Config struct {
	// Enabled activates deception features.
	Enabled bool

	// Honeytokens defines the list of fake files to inject.
	Honeytokens []HoneytokenDef

	// OverlayDir is the base directory for overlayfs work dirs
	// (default: /tmp/providapt-honeypot).
	OverlayDir string

	// CGroupMount is the cgroup v2 mount point (default: /sys/fs/cgroup).
	CGroupMount string

	// CGroupName is the cgroup subgroup name for frozen processes
	// (default: providapt-freeze).
	CGroupName string

	// CPUQuota is the CPU quota for frozen processes as a percentage
	// (default: 1, meaning 1% of a single core).
	CPUQuota int

	// PreserveContext, when true, captures /proc/PID/{maps,fd,env}
	// on freeze (default: true).
	PreserveContext bool

	// OnTrigger, if set, is called when a honeytoken is triggered.
	OnTrigger func(trigger *HoneypotTrigger)

	// GraphUpdater, if set, is called to update provenance node attrs.
	GraphUpdater func(nodeID string, attrs map[string]string)
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Enabled:          true,
		Honeytokens:      DefaultHoneytokens(),
		OverlayDir:       "/tmp/providapt-honeypot",
		CGroupMount:      "/sys/fs/cgroup",
		CGroupName:       "providapt-freeze",
		CPUQuota:         1,
		PreserveContext:  true,
	}
}

// DefaultHoneytokens returns a standard set of decoy files.
func DefaultHoneytokens() []HoneytokenDef {
	return []HoneytokenDef{
		{
			Path:     "/tmp/backup_credentials.xml",
			Type:     HoneytokenCredentials,
			Label:    "数据库备份凭据 — 诱饵文件",
			Tripwire: true,
			Content:  `<?xml version="1.0"?><credentials><database host="prod-db-01.internal" port="3306" user="root" password="P@ssw0rd_Prod!2024"/></credentials>`,
		},
		{
			Path:     "/var/tmp/db_backup_2024.sql",
			Type:     HoneytokenBackup,
			Label:    "数据库备份 — 诱饵文件",
			Tripwire: true,
			Content:  "-- MySQL dump 8.0\nCREATE DATABASE `production`;\nINSERT INTO `users` VALUES (1,'admin','$2a$10$...');\n",
		},
		{
			Path:     "/home/deploy/.ssh/id_rsa_backup",
			Type:     HoneytokenKey,
			Label:    "SSH 私钥 — 诱饵文件",
			Tripwire: false,
			Content:  "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlw...\n-----END OPENSSH PRIVATE KEY-----\n",
		},
		{
			Path:     "/etc/providapt/config_backup.json",
			Type:     HoneytokenConfig,
			Label:    "系统配置备份 — 诱饵文件",
			Tripwire: true,
			Content:  `{"api_key":"sk-prod-xxxxxxxxxxxx","vault_addr":"https://vault.internal:8200","vault_token":"hvs.prod.xxxx"}`,
		},
		{
			Path:     "/root/.kube/config_backup",
			Type:     HoneytokenKubeconfig,
			Label:    "K8s 管理员配置 — 诱饵文件",
			Tripwire: true,
			Content:  "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://k8s-prod.internal:6443\n    certificate-authority-data: LS0t...\n",
		},
	}
}

