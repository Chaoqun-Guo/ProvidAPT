/* SPDX-License-Identifier: GPL-2.0
 *
 * ProvidAPT — eBPF LSM provenance monitor (optimised)
 *
 * Optimisations:
 *   1. PID whitelist  — process PIDs in this map skip ALL event emission.
 *   2. Adaptive sampling — file_permission uses kernel-side counters;
 *      only reports when count >= 1000 OR last report was 1+ second ago.
 *   3. Context-aware taint — processes without taint flags only produce
 *      core events (fork, exec); tainted or network-connecting processes
 *      get full detail.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "providapt.h"
#include "taint.h"
#include "dedup.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* ============================================================
 * BPF helpers
 * ============================================================ */
static long (*bpf_d_path)(struct path *path, char *buf, u32 sz) = (void *)194;

/* ============================================================
 * Maps
 * ============================================================ */

/* ── Ring buffer ─────────────────────────────────────── */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} rb SEC(".maps");

/* ── Process ancestry — child_pid → parent_pid ────────── */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_MAX_ENTRIES);
	__type(key, u32);
	__type(value, u32);
} proc_map SEC(".maps");

/* ── PID whitelist — PIDs in this map skip all events ───
 * Populated by userspace via the control package.
 * Key: PID to exclude.  Value: reserved (set to 1).
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u32);
} pid_whitelist SEC(".maps");

/* ── Taint map — per-process taint flags ────────────────
 * Set by the LSM hooks when suspicious activity is observed.
 * Read by every hook to decide detail level.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_MAX_ENTRIES);
	__type(key, u32);    /* PID */
	__type(value, u32);  /* TAINT_* bitmask */
} taint_map SEC(".maps");

/* ── Sampling counters — adaptive sampling for high-freq hooks ─
 * Key:   (pid << 32) | hook_id
 * Value: [31:0]  accumulated count
 *        [63:32] last report time (monotonic ns, shifted right)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u64);
} sample_counters SEC(".maps");

/* ============================================================
 * Inline helpers
 * ============================================================ */

/* ── should_skip — returns true if pid is whitelisted ─── */
static __always_inline bool should_skip(u32 pid) {
	return bpf_map_lookup_elem(&pid_whitelist, &pid) != NULL;
}

/* ── get_detail — returns detail level for a process ──── */
static __always_inline enum detail_level get_detail(u32 pid) {
	u32 *flags = bpf_map_lookup_elem(&taint_map, &pid);
	if (flags && *flags != 0)
		return DETAIL_FULL;
	return DETAIL_NORMAL;
}

/* ── is_external_ip — non-loopback, non-link-local IPv4 ──── */
static __always_inline bool is_external_ip(u32 addr) {
	/* 127.0.0.0/8      loopback */
	if ((addr & 0xFF) == 0x7F)  return false;
	/* 10.0.0.0/8       RFC 1918 */
	if ((addr & 0xFF) == 0x0A)  return false;
	/* 172.16.0.0/12    RFC 1918 */
	if ((addr & 0xF0) == 0x10)  return false;
	/* 192.168.0.0/16   RFC 1918 */
	if ((addr & 0xFF) == 0xC0 && (addr >> 8 & 0xFF) == 0xA8) return false;
	/* 169.254.0.0/16   link-local */
	if ((addr & 0xFF) == 0xA9 && (addr >> 8 & 0xFF) == 0xFE) return false;
	return true;
}

/* ── is_sensitive_prefix — fast path prefix check ────── */
static __always_inline bool is_sensitive_path(const char *path, u32 max_len) {
#pragma unroll
	for (u32 i = 0; i < max_len; i++) {
		char c;
		bpf_probe_read_kernel(&c, 1, &path[i]);
		if (c == 0) break;

		/* Check "/etc/" at position 0 */
		if (i == 0) {
			char etc[5];
			bpf_probe_read_kernel(etc, 5, path);
			if (etc[0] == '/' && etc[1] == 'e' && etc[2] == 't' && etc[3] == 'c' && etc[4] == '/')
				return true;
		}
		/* Check "/root/" */
		if (i == 0) {
			char root[6];
			bpf_probe_read_kernel(root, 6, path);
			if (root[0] == '/' && root[1] == 'r' && root[2] == 'o' && root[3] == 'o' && root[4] == 't' && root[5] == '/')
				return true;
		}
		/* Check "/home/" */
		if (i == 0) {
			char home[6];
			bpf_probe_read_kernel(home, 6, path);
			if (home[0] == '/' && home[1] == 'h' && home[2] == 'o' && home[3] == 'm' && home[4] == 'e' && home[5] == '/')
				return true;
		}
		/* Check for /etc/shadow anywhere */
		if (c == 's') {
			char shadow[7];
			bpf_probe_read_kernel(shadow, 7, &path[i]);
			if (shadow[0] == 's' && shadow[1] == 'h' && shadow[2] == 'a' &&
			    shadow[3] == 'd' && shadow[4] == 'o' && shadow[5] == 'w')
				return true;
		}
		/* Check for /etc/passwd */
		if (c == 'p') {
			char passwd[7];
			bpf_probe_read_kernel(passwd, 7, &path[i]);
			if (passwd[0] == 'p' && passwd[1] == 'a' && passwd[2] == 's' &&
			    passwd[3] == 's' && passwd[4] == 'w' && passwd[5] == 'd')
				return true;
		}
	}
	return false;
}

/* ── fill_file_path — full path via bpf_d_path ───────── */
static __always_inline void fill_file_path(struct file *file, char *dst, u32 dst_sz) {
	if (!file) { bpf_probe_read_kernel_str(dst, dst_sz, "?"); return; }
	long ret = bpf_d_path(&file->f_path, dst, dst_sz);
	if (ret > 0) return;
	struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
	if (d) { const unsigned char *n = BPF_CORE_READ(d, d_name.name);
		if (n) { bpf_probe_read_kernel_str(dst, dst_sz, n); return; } }
	bpf_probe_read_kernel_str(dst, dst_sz, "?");
}

/* ── fill_event_hdr — populate standard header fields ── */
static __always_inline void fill_event_hdr(struct event *e, u32 type) {
	struct task_struct *current;
	e->type = type;
	e->flags = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid  = bpf_get_current_pid_tgid() >> 32;
	e->tid  = (u32)bpf_get_current_pid_tgid();
	e->uid  = bpf_get_current_uid_gid() >> 32;
	e->gid  = (u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	{	u32 *pp = bpf_map_lookup_elem(&proc_map, &e->pid);
		if (pp) { e->ppid = *pp; }
		else { current = (struct task_struct *)bpf_get_current_task();
			e->ppid = BPF_CORE_READ(current, real_parent, pid); } }
}

/* ── fill_file_payload — inode / device / mode / flags ─ */
static __always_inline void fill_file_payload(struct file_payload *fp, struct file *file) {
	if (!file) { __builtin_memset(fp, 0, sizeof(*fp)); return; }
	fp->f_flags = BPF_CORE_READ(file, f_flags);
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode) { fp->inode = 0; fp->dev_major = 0; fp->dev_minor = 0; fp->mode = 0; return; }
	fp->inode = BPF_CORE_READ(inode, i_ino);
	fp->mode  = BPF_CORE_READ(inode, i_mode);
	u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
	fp->dev_major = dev >> 20;
	fp->dev_minor = dev & MINORMASK;
}

/* ============================================================
 * Adaptive sampling — used by high-frequency hooks
 * ============================================================ */

/* try_sample — accumulate count, report only when threshold crossed.
 * Returns true if the caller should emit a full event (first hit or
 * threshold crossed); false means the event was sampled (merged).
 */
static __always_inline bool try_sample(u32 pid, u32 hook_id) {
	u64 key = ((u64)pid << 32) | hook_id;
	u64 *val = bpf_map_lookup_elem(&sample_counters, &key);
	u64 now = bpf_ktime_get_ns();

	if (val) {
		u32 count  = (u32)(*val & 0xFFFFFFFF);
		u64 last   = (*val >> 32);
		u32 new_count = count + 1;

		if (new_count >= SAMPLE_THRESHOLD || (now - last) >= SAMPLE_INTERVAL_NS) {
			/* Emit aggregated sample event */
			struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
			if (e) {
				fill_event_hdr(e, EV_SAMPLE);
				e->sample_hook_id = hook_id;
				e->sample_count   = new_count;
				bpf_ringbuf_submit(e, 0);
			}
			/* Reset counter */
			u64 reset = now << 32 | 1;
			bpf_map_update_elem(&sample_counters, &key, &reset, BPF_ANY);
			return false; /* sampled — caller skips individual event */
		} else {
			u64 update = ((u64)last << 32) | new_count;
			bpf_map_update_elem(&sample_counters, &key, &update, BPF_ANY);
			return false; /* sampled — merged into counter */
		}
	} else {
		/* First occurrence — initialise counter and emit */
		u64 init = (now << 32) | 1;
		bpf_map_update_elem(&sample_counters, &key, &init, BPF_ANY);
		return true; /* emit full event */
	}
}

/* ============================================================
 * LSM hooks
 * ============================================================ */

/* ── task_alloc ────────────────────────────────────────
 * Core event — NOT subject to taint filtering.
 * Also propagates taint from parent to child.
 */
SEC("lsm/task_alloc")
int BPF_PROG(probe_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
	u32 child_pid  = BPF_CORE_READ(task, pid);
	u32 parent_pid = bpf_get_current_pid_tgid() >> 32;

	if (should_skip(child_pid) || should_skip(parent_pid))
		goto seed_proc;

	/* Taint inheritance: parent → child */
	u32 *pt = bpf_map_lookup_elem(&taint_map, &parent_pid);
	if (pt && *pt != 0) {
		u32 inherited = *pt | TAINT_PARENT;
		bpf_map_update_elem(&taint_map, &child_pid, &inherited, BPF_ANY);
	}

	/* Emit fork event */
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) goto seed_proc;

	fill_event_hdr(e, EV_PROCESS_FORK);
	e->payload.fork.child_pid = child_pid;
	bpf_ringbuf_submit(e, 0);

seed_proc:
	bpf_map_update_elem(&proc_map, &child_pid, &parent_pid, BPF_ANY);
	return 0;
}

/* ── task_free — cleanup ─────────────────────────────── */
SEC("lsm/task_free")
int BPF_PROG(probe_task_free, struct task_struct *task)
{
	u32 pid = BPF_CORE_READ(task, pid);
	bpf_map_delete_elem(&proc_map, &pid);
	bpf_map_delete_elem(&taint_map, &pid);
	return 0;
}

/* ── bprm_check_security — exec ────────────────────────
 * Core event — always emitted.
 */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(probe_bprm_check, struct linux_binprm *bprm)
{
	struct event *e;
	struct file *exe_file;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 detail = get_detail(pid);

	if (should_skip(pid)) return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	fill_event_hdr(e, EV_PROCESS_EXEC);
	exe_file = BPF_CORE_READ(bprm, file);
	if (exe_file) {
		fill_file_payload(&e->payload.file, exe_file);
		if (detail >= DETAIL_FULL)
			fill_file_path(exe_file, e->pathname, sizeof(e->pathname));
		else
			bpf_probe_read_kernel_str(e->pathname, sizeof(e->pathname), "…");
	} else {
		__builtin_memset(&e->payload.file, 0, sizeof(e->payload.file));
		bpf_probe_read_kernel_str(e->pathname, sizeof(e->pathname), "?");
	}
	/* setuid check */
	if (bprm) {
		struct cred *new_cred = BPF_CORE_READ(bprm, cred);
		if (new_cred) {
			__u32 uv = BPF_CORE_READ(new_cred, uid.val);
			__u32 ev = BPF_CORE_READ(new_cred, euid.val);
			if (uv != ev) {
				e->flags |= EV_FLAG_EXEC_SETUID;
				bpf_map_update_elem(&taint_map, &pid, &TAINT_SETUID, BPF_ANY);
			}
		}
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── file_open ──────────────────────────────────────────
 * Context-aware: non-tainted processes only get file_open
 * events; tainted processes get full path detail.
 * Write to sensitive paths → sets TAINT_FILE_WRITE.
 */
SEC("lsm.s/file_open")
int BPF_PROG(probe_file_open, struct file *file)
{
	struct event *e;
	u32 f_flags, type;
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (!file || should_skip(pid)) return 0;

	f_flags = BPF_CORE_READ(file, f_flags);

	/* If writing, check if path is sensitive → set taint */
	if (f_flags & (O_WRONLY | O_RDWR)) {
		char tmp[PATH_MAX_LEN];
		fill_file_path(file, tmp, sizeof(tmp));
		if (is_sensitive_path(tmp, sizeof(tmp))) {
			u32 taint = TAINT_FILE_WRITE;
			bpf_map_update_elem(&taint_map, &pid, &taint, BPF_ANY);
		}
	}

	/* Non-tainted processes: only emit create/modify events (not reads) */
	if (get_detail(pid) < DETAIL_NORMAL && !(f_flags & (O_WRONLY | O_RDWR | O_CREAT)))
		return 0;

	/* Classify event type */
	type = EV_FILE_OPEN;
	if (f_flags & (O_WRONLY | O_RDWR)) {
		type = EV_FILE_MODIFY;
		if (f_flags & O_CREAT) type = EV_FILE_CREATE;
	}


		/* Dedup: skip ring buffer if repeated within 100ms */
		{
			char _p[16];
			fill_file_path(file, _p, sizeof(_p));
			if (try_dedup(pid, type, 0, _p, sizeof(_p)))
				return 0;
		}
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	fill_event_hdr(e, type);
	fill_file_payload(&e->payload.file, file);
	if (get_detail(pid) >= DETAIL_FULL)
		fill_file_path(file, e->pathname, sizeof(e->pathname));
	else
		__builtin_memcpy(e->pathname, "…", 4);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── file_permission ────────────────────────────────────
 * High-frequency → adaptive sampling.
 * Only emitted for tainted processes.
 */
SEC("lsm/file_permission")
int BPF_PROG(probe_file_permission, struct file *file, int mask)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!file || should_skip(pid)) return 0;

	/* Only tainted processes get fine-grained permission events */
	if (get_detail(pid) < DETAIL_FULL)
		return 0;

	/* Adaptive sampling */
	try_sample(pid, EV_FILE_OPEN);
	return 0;
}

/* ── socket_connect ─────────────────────────────────────
 * Sets taint on external (non-loopback) connections.
 * Always emitted to detect C2 / exfiltration.
 */
SEC("lsm.s/socket_connect")
int BPF_PROG(probe_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	struct event *e;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (should_skip(pid)) return 0;

	if (!address || address->sa_family != AF_INET)
		return 0;

	struct sockaddr_in *in = (struct sockaddr_in *)address;
	u32 daddr = BPF_CORE_READ(in, sin_addr.s_addr);

	if (is_external_ip(daddr)) {
		u32 taint = TAINT_NET_CONNECT;
		bpf_map_update_elem(&taint_map, &pid, &taint, BPF_ANY);
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	fill_event_hdr(e, EV_NET_CONNECT);
	e->payload.net.daddr = daddr;
	e->payload.net.dport = BPF_CORE_READ(in, sin_port);
	e->payload.net.protocol = IPPROTO_TCP;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
