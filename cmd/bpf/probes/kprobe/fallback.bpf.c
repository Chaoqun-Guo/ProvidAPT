/* SPDX-License-Identifier: GPL-2.0 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "providapt.h"
#include "taint.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u32);
} pid_whitelist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_MAX_ENTRIES);
	__type(key, u32);
	__type(value, u32);
} taint_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u64);
} sample_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, u32);
} hot_paths SEC(".maps");

static __always_inline bool should_skip(u32 pid) {
	return bpf_map_lookup_elem(&pid_whitelist, &pid) != NULL;
}

static __always_inline enum detail_level get_detail(u32 pid) {
	u32 *flags = bpf_map_lookup_elem(&taint_map, &pid);
	if (flags && *flags != 0)
		return DETAIL_FULL;
	return DETAIL_NORMAL;
}

static __always_inline bool is_external_ip(u32 addr) {
	if ((addr & 0xFF) == 0x7F) return false;
	if ((addr & 0xFF) == 0x0A) return false;
	if ((addr & 0xF0) == 0x10) return false;
	if ((addr & 0xFF) == 0xC0 && (addr >> 8 & 0xFF) == 0xA8) return false;
	if ((addr & 0xFF) == 0xA9 && (addr >> 8 & 0xFF) == 0xFE) return false;
	return true;
}

static __always_inline bool is_sensitive_path(const char *path, u32 max_len) {
	char tmp[6];
	if (!path || max_len == 0)
		return false;

	bpf_probe_read_kernel_str(tmp, sizeof(tmp), path);
	if (tmp[0] == '/' && tmp[1] == 'e' && tmp[2] == 't' && tmp[3] == 'c' && tmp[4] == '/')
		return true;
	if (tmp[0] == '/' && tmp[1] == 'r' && tmp[2] == 'o' && tmp[3] == 'o' && tmp[4] == 't' && tmp[5] == '/')
		return true;
	if (tmp[0] == '/' && tmp[1] == 'h' && tmp[2] == 'o' && tmp[3] == 'm' && tmp[4] == 'e' && tmp[5] == '/')
		return true;
	return false;
}

static __always_inline void fill_file_path(struct file *file, char *dst, u32 dst_sz) {
	if (!file) {
		bpf_probe_read_kernel_str(dst, dst_sz, "?");
		return;
	}
	struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
	if (d) {
		const unsigned char *n = BPF_CORE_READ(d, d_name.name);
		if (n) {
			bpf_probe_read_kernel_str(dst, dst_sz, n);
			return;
		}
	}
	bpf_probe_read_kernel_str(dst, dst_sz, "?");
}

static __always_inline void fill_event_hdr(struct event *e, u32 type) {
	e->type = type;
	e->flags = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() >> 32;
	e->gid = (u32)bpf_get_current_uid_gid();
	e->ppid = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void fill_file_payload(struct file_payload *fp, struct file *file) {
	if (!file) {
		__builtin_memset(fp, 0, sizeof(*fp));
		return;
	}
	fp->f_flags = BPF_CORE_READ(file, f_flags);
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode) {
		fp->inode = 0;
		fp->dev_major = 0;
		fp->dev_minor = 0;
		fp->mode = 0;
		return;
	}
	fp->inode = BPF_CORE_READ(inode, i_ino);
	fp->mode = BPF_CORE_READ(inode, i_mode);
	u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
	fp->dev_major = dev >> 20;
	fp->dev_minor = dev & MINORMASK;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(probe_file_open, struct file *file)
{
	struct event *e;
	u32 type, f_flags;
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (!file || should_skip(pid))
		return 0;

	f_flags = BPF_CORE_READ(file, f_flags);
	type = EV_FILE_OPEN;
	if (f_flags & (O_WRONLY | O_RDWR)) {
		type = EV_FILE_MODIFY;
		if (f_flags & O_CREAT)
			type = EV_FILE_CREATE;
	}

	if (type != EV_FILE_OPEN) {
		char tmp[PATH_MAX_LEN];
		fill_file_path(file, tmp, sizeof(tmp));
		if (is_sensitive_path(tmp, sizeof(tmp))) {
			u32 taint = TAINT_FILE_WRITE;
			bpf_map_update_elem(&taint_map, &pid, &taint, BPF_ANY);
		}
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_event_hdr(e, type);
	fill_file_payload(&e->payload.file, file);
	if (get_detail(pid) >= DETAIL_NORMAL)
		fill_file_path(file, e->pathname, sizeof(e->pathname));
	else
		bpf_probe_read_kernel_str(e->pathname, sizeof(e->pathname), "?");

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(probe_bprm_check, struct linux_binprm *bprm)
{
	struct event *e;
	struct file *exe_file;
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (should_skip(pid))
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_event_hdr(e, EV_PROCESS_EXEC);
	exe_file = BPF_CORE_READ(bprm, file);
	if (exe_file) {
		fill_file_payload(&e->payload.file, exe_file);
		fill_file_path(exe_file, e->pathname, sizeof(e->pathname));
	} else {
		__builtin_memset(&e->payload.file, 0, sizeof(e->payload.file));
		bpf_probe_read_kernel_str(e->pathname, sizeof(e->pathname), "?");
	}

	if (bprm) {
		struct cred *new_cred = BPF_CORE_READ(bprm, cred);
		if (new_cred) {
			__u32 uv = BPF_CORE_READ(new_cred, uid.val);
			__u32 ev = BPF_CORE_READ(new_cred, euid.val);
			if (uv != ev) {
				u32 taint = TAINT_SETUID;
				e->flags |= EV_FLAG_EXEC_SETUID;
				bpf_map_update_elem(&taint_map, &pid, &taint, BPF_ANY);
			}
		}
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/copy_process")
int BPF_KPROBE(probe_task_alloc)
{
	return 0;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(probe_task_free)
{
	return 0;
}

SEC("kprobe/security_file_permission")
int BPF_KPROBE(probe_file_permission, struct file *file, int mask)
{
	struct event *e;
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (!file || should_skip(pid))
		return 0;

	if (get_detail(pid) < DETAIL_FULL)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_event_hdr(e, EV_FILE_OPEN);
	fill_file_payload(&e->payload.file, file);
	fill_file_path(file, e->pathname, sizeof(e->pathname));
	e->sample_hook_id = EV_FILE_OPEN;
	e->sample_count = 1;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/__sys_connect")
int BPF_KPROBE(probe_socket_connect, int fd, struct sockaddr *uservaddr, int addrlen)
{
	struct event *e;
	struct sockaddr_in addr = {};
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (should_skip(pid) || !uservaddr)
		return 0;

	if (bpf_probe_read_user(&addr, sizeof(addr), uservaddr) != 0)
		return 0;
	if (addr.sin_family != AF_INET)
		return 0;

	if (is_external_ip(addr.sin_addr.s_addr)) {
		u32 taint = TAINT_NET_CONNECT;
		bpf_map_update_elem(&taint_map, &pid, &taint, BPF_ANY);
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_event_hdr(e, EV_NET_CONNECT);
	e->payload.net.saddr = 0;
	e->payload.net.sport = 0;
	e->payload.net.daddr = addr.sin_addr.s_addr;
	e->payload.net.dport = addr.sin_port;
	e->payload.net.protocol = IPPROTO_TCP;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
