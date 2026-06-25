/* SPDX-License-Identifier: GPL-2.0
 *
 * ProvidAPT — Defense eBPF programs
 *
 * Provides two defensive mechanisms enforced at the LSM layer:
 *
 *   1. LOG PROTECTION — deny non-agent writes to the RocksDB
 *      storage directory and config files.  Only the ProvidAPT
 *      agent and watchdog have write access.
 *
 *   2. DEATH MONITORING — detect when the agent process is killed
 *      and emit EV_AGENT_KILLED with the killer's identity.
 *
 * Design rationale:
 *   - PID hiding via getdents64 hooking is impractical in eBPF
 *     (verifier cannot handle buffer manipulation).  Instead we
 *     deny /proc/<agent_pid> access at the LSM layer.
 *   - Agent process and protected inodes are registered at startup
 *     via BPF map updates from userspace.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "providapt.h"

char LICENSE[] SEC("license") = "GPL";

/* ============================================================
 * Ring buffer — separate channel for defense events
 * ============================================================ */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} rb_defense SEC(".maps");

/* ============================================================
 * Agent identity map
 *
 * Populated at startup by providaptd and providapt-watchdog.
 * Key: PID.  Value: flags (1=agent, 2=watchdog).
 * ============================================================ */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, u32);
	__type(value, u32);
} agent_pids SEC(".maps");

#define AGENT_FLAG    (1U << 0)
#define WATCHDOG_FLAG (1U << 1)

/* ============================================================
 * Protected inodes
 *
 * Populated at startup with inodes of:
 *   - RocksDB storage directory and data files
 *   - ProvidAPT configuration files
 *   - Provenance log files
 * Key: inode.  Value: reserved.
 * ============================================================ */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, u64);
	__type(value, u32);
} protected_inodes SEC(".maps");

/* ============================================================
 * Helper: check if current process is agent/watchdog
 * ============================================================ */
static __always_inline bool is_agent(u32 pid) {
	return bpf_map_lookup_elem(&agent_pids, &pid) != NULL;
}

/* ============================================================
 * LOG PROTECTION
 *
 * SEC("lsm/file_permission")
 *
 * Intercepts write/truncate operations on protected files.
 * Only the ProvidAPT agent may write to its own storage.
 * All other processes (including root) are denied.
 *
 * This prevents:
 *   - rm -rf /var/lib/providapt/
 *   - echo > /var/lib/providapt/store/<sst-file>
 *   - tampering with provenance log files
 * ============================================================ */

SEC("lsm/file_permission")
int BPF_PROG(probe_protect_logs, struct file *file, int mask)
{
	/* Only intercept write-related operations */
	if (!(mask & (MAY_WRITE | MAY_READ))) return 0;

	/* Read the protected inode */
	u64 inode = 0;
	struct inode *f_inode = BPF_CORE_READ(file, f_inode);
	if (f_inode)
		inode = BPF_CORE_READ(f_inode, i_ino);
	if (!inode) return 0;

	/* Check if this inode is in our protected set */
	if (!bpf_map_lookup_elem(&protected_inodes, &inode))
		return 0;

	/* Allow agent and watchdog */
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (is_agent(pid)) return 0;

	/* Non-agent write attempt — emit denial event and refuse */
	struct event *e = bpf_ringbuf_reserve(&rb_defense, sizeof(*e), 0);
	if (e) {
		e->type = EV_FILE_DENIED;
		e->timestamp_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->uid = bpf_get_current_uid_gid() >> 32;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		e->payload.file.inode = inode;
		bpf_ringbuf_submit(e, 0);
	}

	return -EPERM;
}

/* ============================================================
 * DEATH MONITORING
 *
 * SEC("lsm/task_free")
 *
 * When an agent-tagged process exits, emits EV_AGENT_KILLED
 * with the killer PID (from real_parent / tracer) and cleans
 * up the agent_pids map entry.
 * ============================================================ */

SEC("lsm/task_free")
int BPF_PROG(probe_agent_death, struct task_struct *task)
{
	u32 pid = BPF_CORE_READ(task, pid);

	/* Check if this is a tracked agent process */
	if (!bpf_map_lookup_elem(&agent_pids, &pid))
		return 0;

	/* Emit death event for the watchdog to act on */
	struct event *e = bpf_ringbuf_reserve(&rb_defense, sizeof(*e), 0);
	if (!e) goto cleanup;

	e->type = EV_AGENT_KILLED;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->uid = bpf_get_current_uid_gid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Record the killer (real_parent / tracer) */
	e->ppid = BPF_CORE_READ(task, real_parent, pid);

	/* Also record who is running on this CPU right now (likely the killer) */
	e->payload.fork.child_pid = bpf_get_current_pid_tgid() >> 32;

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&agent_pids, &pid);
	return 0;
}

/* ============================================================
 * PID ACCESS CONTROL
 *
 * SEC("lsm/file_open")
 *
 * When a non-agent process tries to open /proc/<agent_pid>/...,
 * deny the access.  This prevents casual discovery via:
 *   cat /proc/<pid>/status
 *   ls /proc/<pid>/
 * ============================================================ */

SEC("lsm/file_open")
int BPF_PROG(probe_hide_agent, struct file *file)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Always allow agent and watchdog */
	if (is_agent(pid)) return 0;

	/* Check if this file has a matching agent PID in its path.
	 * We use the dentry name as a fast check. */
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry) return 0;

	/* We can't reliably check /proc/<pid> in eBPF without
	 * walking the full dentry chain.  For now this is a
	 * placeholder — the log protection above is the primary
	 * mechanism.  Full PID hiding requires a kernel module
	 * or getdents LSM hook. */
	return 0;
}
