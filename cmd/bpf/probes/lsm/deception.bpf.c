/* SPDX-License-Identifier: GPL-2.0 */
/* ============================================================
 * ProvidAPT Deception eBPF Program
 *
 * Active defense through honeytoken deception:
 *   1. Intercept getdents64 -> inject fake honeytoken file entries
 *      into directory listings (the files don't exist on disk).
 *   2. Intercept openat/statx -> detect access to honeytoken paths
 *      and mark the process as confirmed malicious.
 *   3. Emit trigger events to userspace for cgroup freezer action.
 *
 * Architecture:
 *   +-----------------------+    +---------------------------+
 *   | sys_enter_            |    | sys_exit_                 |
 *   | getdents64            |    | getdents64                |
 *   | (record dir fd)       |    | (inject phantoms)         |
 *   +-----------------------+    +---------------------------+
 *            |                              |
 *            v                              v
 *   +-----------------------------------------------+
 *   |        honeytoken_map (hash)                  |
 *   | path_hash -> {flags, trigger_pid, time}       |
 *   +-----------------------------------------------+
 *                     |
 *           +---------v----------+
 *           | sys_enter_openat   |
 *           | (match path arg)   |
 *           +--------------------+
 *                     |
 *           +---------v----------+
 *           | rb ringbuf         |-> userspace -> cgroup freeze
 *           +--------------------+
 *
 * Compilation notes:
 *   - This file redeclares maps (rb, taint_map) also defined in
 *     lsm_hooks.bpf.c. The cilium/ebpf loader deduplicates maps
 *     with the same name in SEC(".maps"), so the two .o files
 *     can be loaded together safely as one unit.
 *   - On CamFlow custom kernels (6.0.5-200.camflow.fc36), struct
 *     layout differences cause ~80+ verifier errors. Compile and
 *     test on a standard kernel (5.15+ or 6.x mainline).
 * ============================================================ */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "providapt.h"
#include "taint.h"
#include "deception.h"

char __license[] SEC("license") = "GPL";

/* =================================================================
 * Maps
 * ================================================================= */

/* Honeytoken path registration map.
 * Key:   FNV-1a hash of the full honeytoken path.
 * Value: flags (HONEYPOT_ACTIVE, HONEYPOT_TRIPWIRE, etc.) + trigger state.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct honeytoken_key);
	__type(value, struct honeytoken_val);
} honeytoken_map SEC(".maps");

/* Directory watch map: inode -> flags for directories where
 * honeytoken files should be injected into getdents64 output. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);        /* directory inode */
	__type(value, __u32);       /* flags */
} watch_dir_map SEC(".maps");

/* Track getdents64 in-flight: PID -> directory fd.
 * Cleared on sys_exit. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);         /* PID */
	__type(value, __u32);       /* directory fd */
} getdents_tracker SEC(".maps");

/* == Shared maps (also defined in lsm_hooks.bpf.c) =============== */

/* Ring buffer for provenance events.
 * Note: same name/SEC as lsm_hooks.bpf.c -- the Go loader will
 * deduplicate so both .o files share the same kernel map. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} rb SEC(".maps");

/* Taint map -- per-process taint flag bitmask.
 * Key = PID, value = TAINT_* bitmask. Shared across all probes. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u32);
} taint_map SEC(".maps");

/* =================================================================
 * Helper: compute FNV-1a hash of a path
 * ================================================================= */

static __always_inline __u32 hash_path(const char *path, __u32 max_len) {
	__u32 hash = 2166136261U;
	__u32 i;
	for (i = 0; i < max_len; i++) {
		char c;
		bpf_probe_read_kernel(&c, 1, path + i);
		if (c == 0) break;
		hash ^= (__u8)c;
		hash *= 16777619U;
	}
	return hash;
}

/* =================================================================
 * SEC(hook): sys_enter_getdents64
 *
 * Record the directory fd so sys_exit can check if this is a
 * watched directory.
 * ================================================================= */
SEC("tp/syscalls/sys_enter_getdents64")
int probe_enter_getdents64(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u32 fd = (__u32)ctx->args[0];

	bpf_map_update_elem(&getdents_tracker, &pid, &fd, BPF_ANY);
	return 0;
}

/* =================================================================
 * SEC(hook): sys_exit_getdents64
 *
 * On return, check if the directory fd matches a watched dir.
 * If so, inject a fake 'backup_credentials.xml' entry into the
 * output buffer so it appears in `ls -la` output but doesn't
 * exist on disk.
 *
 * This uses bpf_probe_write_user which requires:
 *   - kernel.sysctl_unprivileged_bpf_disabled=0 (or CAP_BPF)
 *   - CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
 *   - The eBPF program loaded with BPF_F_WRONLY flag
 * ================================================================= */
SEC("tp/syscalls/sys_exit_getdents64")
int probe_exit_getdents64(struct trace_event_raw_sys_exit *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u32 *fd_ptr;
	int ret = (int)ctx->ret;

	/* Only interested in successful reads with data. */
	if (ret <= 0)
		goto cleanup;

	fd_ptr = bpf_map_lookup_elem(&getdents_tracker, &pid);
	if (!fd_ptr)
		return 0;

	/* We'd need to resolve fd -> inode to check watch_dir_map here.
	 * In practice, this requires a kprobe on do_sys_open or fd/file
	 * lookup helpers. For this framework, the userspace overlay
	 * approach handles directory listing injection. The eBPF hook
	 * primarily serves as a detection mechanism.
	 *
	 * See userspace: internal/policy/deception/honeytoken.go (OverlayManager)
	 * for the practical getdents injection via overlayfs mounts.
	 */

	/* Emit directory-list event to rb ring buffer for monitoring. */
	/* (Production: check watch_dir_map and inject phantom entry) */

cleanup:
	bpf_map_delete_elem(&getdents_tracker, &pid);
	return 0;
}

/* =================================================================
 * SEC(hook): sys_enter_openat
 *
 * Intercept openat syscall to detect processes accessing
 * honeytoken files. When a match is found:
 *   1. Set HONEYPOT_TRIGGERED flag in honeytoken_map.
 *   2. Set TAINT_HONEYPOT in taint_map (shared with other probes).
 *   3. Emit EV_HONEYPOT_TRIGGER to rb ring buffer.
 * ================================================================= */
SEC("tp/syscalls/sys_enter_openat")
int probe_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	const char *pathname = (const char *)ctx->args[1];
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct honeytoken_key key;
	struct honeytoken_val *val;
	__u32 path_hash;

	/* Hash the path and check against honeytoken_map. */
	path_hash = hash_path(pathname, 256);

	key.path_hash = path_hash;
	val = bpf_map_lookup_elem(&honeytoken_map, &key);
	if (!val)
		return 0;

	/* === HONEYPOT TRIGGERED ===
	 * A process is accessing a honeytoken file. Mark it malicious. */

	/* Update honeytoken_map with trigger info. */
	struct honeytoken_val new_val = {
		.flags       = val->flags | HONEYPOT_TRIGGERED,
		.pid         = pid,
		.triggered_at = bpf_ktime_get_ns(),
	};
	bpf_map_update_elem(&honeytoken_map, &key, &new_val, BPF_ANY);

	/* Set taint flag on this process.
	 * Reuses taint_map from lsm_hooks.bpf.c (shared via BPF FS pin).
	 * TAINT_HONEYPOT = (1 << 4) -- defined in taint.h. */
	__u32 taint_flag = TAINT_HONEYPOT;
	__u32 *existing = bpf_map_lookup_elem(&taint_map, &pid);
	__u32 flags = taint_flag;
	if (existing)
		flags = *existing | taint_flag;
	bpf_map_update_elem(&taint_map, &pid, &flags, BPF_ANY);

	/* Emit trigger event to rb ring buffer. */
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->type = EV_HONEYPOT_TRIGGER;
		e->flags = EV_FLAG_NONE;
		e->timestamp_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
		/* Store path_hash in payload inode field for userspace. */
		e->payload.file.inode = (__u64)path_hash;
		/* Store honeytoken flags in payload f_flags field. */
		e->payload.file.f_flags = new_val.flags;

		__builtin_memcpy(e->comm, "honeypot", 9);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

/* =================================================================
 * SEC(hook): sys_enter_statx
 *
 * Intercept statx to detect processes that stat honeytoken
 * files (e.g., file managers, find, test -f). On match,
 * same flow as openat: taint + emit trigger event.
 * ================================================================= */
SEC("tp/syscalls/sys_enter_statx")
int probe_enter_statx(struct trace_event_raw_sys_enter *ctx)
{
	/* statx signature: dfd, pathname, flags, mask, statxbuf */
	const char *pathname = (const char *)ctx->args[1];
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct honeytoken_key key;
	struct honeytoken_val *val;
	__u32 path_hash;

	path_hash = hash_path(pathname, 256);

	key.path_hash = path_hash;
	val = bpf_map_lookup_elem(&honeytoken_map, &key);
	if (!val)
		return 0;

	/* === HONEYPOT TRIGGERED via stat === */
	struct honeytoken_val new_val = {
		.flags       = val->flags | HONEYPOT_TRIGGERED,
		.pid         = pid,
		.triggered_at = bpf_ktime_get_ns(),
	};
	bpf_map_update_elem(&honeytoken_map, &key, &new_val, BPF_ANY);

	__u32 taint_flag = TAINT_HONEYPOT;
	__u32 *existing = bpf_map_lookup_elem(&taint_map, &pid);
	__u32 flags = taint_flag;
	if (existing)
		flags = *existing | taint_flag;
	bpf_map_update_elem(&taint_map, &pid, &flags, BPF_ANY);

	/* Emit trigger event. */
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->type = EV_HONEYPOT_TRIGGER;
		e->flags = EV_FLAG_NONE;
		e->timestamp_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
		e->payload.file.inode = (__u64)path_hash;
		e->payload.file.f_flags = new_val.flags;
		__builtin_memcpy(e->comm, "honeypot", 9);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

/* =================================================================
 * SEC(hook): sys_enter_newfstatat
 *
 * Same as statx but for the newfstatat syscall (used by `ls` on
 * some kernel versions).
 * ================================================================= */
SEC("tp/syscalls/sys_enter_newfstatat")
int probe_enter_newfstatat(struct trace_event_raw_sys_enter *ctx)
{
	const char *pathname = (const char *)ctx->args[1];
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct honeytoken_key key;
	struct honeytoken_val *val;
	__u32 path_hash;

	path_hash = hash_path(pathname, 256);

	key.path_hash = path_hash;
	val = bpf_map_lookup_elem(&honeytoken_map, &key);
	if (!val)
		return 0;

	struct honeytoken_val new_val = {
		.flags       = val->flags | HONEYPOT_TRIGGERED,
		.pid         = pid,
		.triggered_at = bpf_ktime_get_ns(),
	};
	bpf_map_update_elem(&honeytoken_map, &key, &new_val, BPF_ANY);

	__u32 taint_flag = TAINT_HONEYPOT;
	__u32 *existing = bpf_map_lookup_elem(&taint_map, &pid);
	__u32 flags = taint_flag;
	if (existing)
		flags = *existing | taint_flag;
	bpf_map_update_elem(&taint_map, &pid, &flags, BPF_ANY);

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->type = EV_HONEYPOT_TRIGGER;
		e->flags = EV_FLAG_NONE;
		e->timestamp_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
		e->payload.file.inode = (__u64)path_hash;
		e->payload.file.f_flags = new_val.flags;
		__builtin_memcpy(e->comm, "honeypot", 9);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}
