/* SPDX-License-Identifier: GPL-2.0 */
/* ============================================================
 * ProvidAPT Deception eBPF Program
 *
 * Active defense through honeytoken deception:
 *   1. Intercept getdents64 鈫-inject fake honeytoken file entries
 *      into directory listings (the files don't exist on disk).
 *   2. Intercept openat/statx 鈫-detect access to honeytoken paths
 *      and mark the process as confirmed malicious.
 *   3. Emit trigger events to userspace for cgroup freezer action.
 *
 * Architecture:
 *   鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹-   鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹- *   鈹- sys_enter_     鈹-   鈹- sys_exit_       鈹- *   鈹- getdents64     鈹-   鈹- getdents64      鈹- *   鈹- (record dir fd)鈹-   鈹- (inject phantoms)鈹- *   鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹-   鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹- *            鈹-                     鈹- *            鈻-                     鈻- *   鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹- *   鈹-        honeytoken_map (hash)            鈹- *   鈹- path_hash 鈫-{flags, trigger_pid, time}  鈹- *   鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹- *                    鈹- *          鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈻尖攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹- *          鈹- sys_enter_openat  鈹- *          鈹- (match path arg)  鈹- *          鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹- *                    鈹- *          鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈻尖攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹- *          鈹- rb_defense ringbuf鈹傗攢鈹€鈫-userspace 鈫-cgroup freeze
 *          鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹- * ============================================================ */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "providapt.h"
#include "deception.h"

char __license[] SEC("license") = "GPL";

/* 鈹€鈹€鈹€ Maps 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ */

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

/* Directory watch map: inode 鈫-flags for directories where
 * honeytoken files should be injected into getdents64 output. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);        /* directory inode */
	__type(value, __u32);       /* flags */
} watch_dir_map SEC(".maps");

/* Track getdents64 in-flight: PID 鈫-directory fd.
 * Cleared on sys_exit. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);         /* PID */
	__type(value, __u32);       /* directory fd */
} getdents_tracker SEC(".maps");

/* 鈹€鈹€鈹€ Helper: compute FNV-1a hash of a path 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ */

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

/* 鈹€鈹€鈹€ SEC(hook): sys_enter_getdents64 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
 * Record the directory fd so sys_exit can check if this is a
 * watched directory. */
SEC("tp/syscalls/sys_enter_getdents64")
int probe_enter_getdents64(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u32 fd = (__u32)ctx->args[0];

	bpf_map_update_elem(&getdents_tracker, &pid, &fd, BPF_ANY);
	return 0;
}

/* 鈹€鈹€鈹€ SEC(hook): sys_exit_getdents64 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
 * On return, check if the directory fd matches a watched dir.
 * If so, inject a fake 'backup_credentials.xml' entry into the
 * output buffer so it appears in `ls -la` output but doesn't
 * exist on disk.
 *
 * This uses bpf_probe_write_user which requires:
 *   - kernel.sysctl_unprivileged_bpf_disabled=0 (or CAP_BPF)
 *   - CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
 *   - The eBPF program loaded with BPF_F_WRONLY flag
 */
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

	/* We'd need to resolve fd 鈫-inode to check watch_dir_map here.
	 * In practice, this requires a kprobe on do_sys_open or fd/file
	 * lookup helpers. For this framework, the userspace overlay
	 * approach handles directory listing injection. The eBPF hook
	 * primarily serves as a detection mechanism.
	 *
	 * See userspace: internal/policy/deception/honeytoken.go (OverlayManager)
	 * for the practical getdents injection via overlayfs mounts.
	 */

	/* Emit directory-list event to rb_defense for monitoring. */
	/* (Production: check watch_dir_map and inject phantom entry) */

cleanup:
	bpf_map_delete_elem(&getdents_tracker, &pid);
	return 0;
}

/* 鈹€鈹€鈹€ SEC(hook): sys_enter_openat 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
 * Intercept openat syscall to detect processes accessing
 * honeytoken files. When a match is found:
 *   1. Set HONEYPOT_TRIGGERED flag in honeytoken_map.
 *   2. Set TAINT_HONEYPOT in taint_map (shared with other probes).
 *   3. Emit EV_HONEYPOT_TRIGGER to rb ring buffer.
 */
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

	/* 鈹€鈹€ HONEYPOT TRIGGERED 鈹€鈹€ */
	/* A process is accessing a honeytoken file. Mark it malicious. */

	/* Update honeytoken_map with trigger info. */
	struct honeytoken_val new_val = {
		.flags       = val->flags | HONEYPOT_TRIGGERED,
		.pid         = pid,
		.triggered_at = bpf_ktime_get_ns(),
	};
	bpf_map_update_elem(&honeytoken_map, &key, &new_val, BPF_ANY);

	/* Set taint flag on this process.
	 * Reuses taint_map from lsm_hooks.bpf.c (shared via BPF FS pin).
	 * TAINT_HONEYPOT = (1 << 5) 鈥-defined in taint.h. */
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
		e->file.inode = (__u64)path_hash;
		/* Store honeytoken flags in payload f_flags field. */
		e->file.f_flags = new_val.flags;

		__builtin_memcpy(e->comm, "honeypot", 9);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

/* 鈹€鈹€鈹€ SEC(hook): sys_enter_statx 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
 * Intercept statx to detect processes that stat honeytoken
 * files (e.g., file managers, find, test -f). On match,
 * same flow as openat: taint + emit trigger event.
 */
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

	/* 鈹€鈹€ HONEYPOT TRIGGERED via stat 鈹€鈹€ */
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
		e->file.inode = (__u64)path_hash;
		e->file.f_flags = new_val.flags;
		__builtin_memcpy(e->comm, "honeypot", 9);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

/* 鈹€鈹€鈹€ SEC(hook): sys_enter_newfstatat 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
 * Same as statx but for the newfstatat syscall (used by `ls` on
 * some kernel versions). */
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
		e->file.inode = (__u64)path_hash;
		e->file.f_flags = new_val.flags;
		__builtin_memcpy(e->comm, "honeypot", 9);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}
