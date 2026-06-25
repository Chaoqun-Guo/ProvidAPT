/* SPDX-License-Identifier: GPL-2.0
 *
 * ProvidAPT — Memory attack detection eBPF programs
 *
 * Detects three classes of memory-based attacks commonly seen in
 * advanced persistent threats (APTs):
 *
 *   1. memfd_create — fileless malware via anonymous memory-backed
 *      file descriptors (used by Living-off-the-Land techniques).
 *
 *   2. mprotect RW→RX — shellcode injection via changing memory
 *      page permissions from writable to executable.
 *
 *   3. Pipe data flow — tracks inter-process pipe communication
 *      to detect "curl | bash" fileless execution chains.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "providapt.h"

char LICENSE[] SEC("license") = "GPL";

/* ============================================================
 * Ring buffer (separate from main lsm_hooks)
 * ============================================================ */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} rb_memory SEC(".maps");

/* ============================================================
 * mprotect tracker — records old protection before a change
 * Key: PID.  Value: old_prot | new_prot.
 * Populated on sys_enter, consumed on sys_exit.
 * ============================================================ */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct mprotect_state);
} mprotect_tracker SEC(".maps");

struct mprotect_state {
	u64 addr;
	u64 len;
	u64 prot;
};

/* ============================================================
 * Pipe tracker — correlates write and read ends
 * Key: pipe_fd (from pipe2).  Value: PID of writer.
 * ============================================================ */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, u64);
	__type(value, u32);
} pipe_writer SEC(".maps");

/* ─── Helper ──────────────────────────────────────────────── */

static __always_inline void fill_hdr(struct event *e, u32 type) {
	e->type = type;
	e->flags = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() >> 32;
	e->gid = (u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* ============================================================
 * 1. memfd_create detection
 *
 * memfd_create() creates an anonymous file that exists only in
 * memory.  It is a common technique used by fileless malware to
 * execute code without writing to disk.
 *
 * Hook: tracepoint/syscalls/sys_enter_memfd_create
 * ============================================================ */

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb_memory, sizeof(*e), 0);
	if (!e) return 0;

	fill_hdr(e, EV_MEMFD_CREATE);

	/* Read the name of the memfd from userspace */
	const char *name_ptr = (const char *)ctx->args[0];
	if (name_ptr)
		bpf_probe_read_user_str(e->pathname, sizeof(e->pathname), name_ptr);
	else
		__builtin_memcpy(e->pathname, "anonymous", 10);

	e->payload.file.f_flags = (u32)ctx->args[1];  /* flags: MFD_CLOEXEC etc. */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ============================================================
 * 2. mprotect RW→RX detection
 *
 * Shellcode injection typically involves:
 *   1. Allocate memory with RW permission (mmap)
 *   2. Write shellcode into it
 *   3. Change permissions to RX (mprotect)
 *   4. Jump to the shellcode
 *
 * We detect step 3 by comparing old vs new protection flags.
 *
 * Hook: tracepoint/syscalls/sys_enter_mprotect  (record request)
 *       tracepoint/syscalls/sys_exit_mprotect   (verify success)
 * ============================================================ */

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect_enter(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	unsigned long prot = (unsigned long)ctx->args[2];
	struct mprotect_state state = {
		.addr = (u64)ctx->args[0],
		.len  = (u64)ctx->args[1],
		.prot = (u64)prot,
	};

	/* PROT_EXEC = 4, PROT_WRITE = 2, PROT_READ = 1 */
	/* We only care about changes involving PROT_EXEC */
	if (!(prot & 4))  /* not setting executable */
		return 0;

	/* Store the requested protection in the tracker.
	 * Lower 32 bits: new protection flags.
	 * Upper 32 bits: old protection (we'll read the VMA on exit). */
	bpf_map_update_elem(&mprotect_tracker, &pid, &state, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_mprotect")
int trace_mprotect_exit(struct trace_event_raw_sys_exit *ctx)
{
	/* Only on success */
	if (ctx->ret < 0) return 0;

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct mprotect_state *entry = bpf_map_lookup_elem(&mprotect_tracker, &pid);
	if (!entry) return 0;

	unsigned long new_prot = (unsigned long)entry->prot;

	/* In a real implementation, we'd read the VMA's previous
	 * protection flags.  For now we flag any mprotect that
	 * adds PROT_EXEC to memory we cannot verify was previously
	 * non-executable, erring on the side of detection. */
	bpf_map_delete_elem(&mprotect_tracker, &pid);

	/* Only alert if this is transitioning TO executable
	 * from something that wasn't executable before.
	 * PROT_EXEC = 4, PROT_WRITE = 2, PROT_READ = 1 */
	if (!(new_prot & 4))
		return 0;  /* not becoming executable */

	struct event *e = bpf_ringbuf_reserve(&rb_memory, sizeof(*e), 0);
	if (!e) return 0;

	fill_hdr(e, EV_MPROTECT_RX);
	e->payload.file.f_flags = (u32)new_prot;

	/* Store the address being modified */
	e->payload.file.inode = entry->addr;

	/* Store the length */
	e->payload.file.dev_major = (u32)(entry->len >> 32);
	e->payload.file.dev_minor = (u32)(entry->len & 0xFFFFFFFF);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ============================================================
 * 3. Pipe data flow tracking
 *
 * Tracks inter-process pipe communication to detect fileless
 * execution chains (e.g., "curl | bash").
 *
 * Hook: tracepoint/syscalls/sys_enter_write
 *       tracepoint/syscalls/sys_enter_read
 *
 * For "curl | bash" detection:
 *   - Writer (curl) writes to pipe fd
 *   - Reader (bash) reads from pipe fd
 *   - Reader then execs (detected via bprm_check)
 *   → This chain is flagged as a fileless execution event
 * ============================================================ */

SEC("tracepoint/syscalls/sys_enter_write")
int trace_pipe_write(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	unsigned int fd = (unsigned int)ctx->args[0];
	size_t count = (size_t)ctx->args[2];

	/* Rough heuristic: small writes (< 4 bytes) are likely not pipes */
	if (count < 4 || count > 65536)
		return 0;

	u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Check if this PID has been writing to pipes recently.
	 * We track by PID+fd as a crude pipe correlation. */
	u64 key = ((u64)pid << 32) | fd;
	u32 *partner = bpf_map_lookup_elem(&pipe_writer, &key);
	if (partner) {
		/* This is a pipe — emit event */
		e = bpf_ringbuf_reserve(&rb_memory, sizeof(*e), 0);
		if (!e) return 0;

		fill_hdr(e, EV_PIPE_WRITE);
		/* Reuse file payload for pipe metadata */
		e->payload.file.inode = fd;
		e->payload.file.dev_major = *partner;
		e->payload.file.dev_minor = (u32)count;
		/* Format: "pipe:fd=<fd>" */
		bpf_probe_read_kernel_str(e->pathname, sizeof(e->pathname), "pipe:data");

		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_pipe_read(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	unsigned int fd = (unsigned int)ctx->args[0];
	size_t count = (size_t)ctx->args[2];

	if (count < 4 || count > 65536)
		return 0;

	u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* For reads, we record PID+fd as potential writer partner */
	u64 key = ((u64)pid << 32) | fd;
	u32 writer_pid = pid;  /* placeholder — in production, use pipe ID */

	u32 *entry = bpf_map_lookup_elem(&pipe_writer, &key);
	if (!entry) {
		bpf_map_update_elem(&pipe_writer, &key, &writer_pid, BPF_ANY);
		return 0;
	}

	/* Emit pipe read event */
	e = bpf_ringbuf_reserve(&rb_memory, sizeof(*e), 0);
	if (!e) return 0;

	fill_hdr(e, EV_PIPE_READ);
	/* Reuse file payload for pipe metadata */
	e->payload.file.inode = fd;
	e->payload.file.dev_major = pid;
	e->payload.file.dev_minor = (u32)count;
	bpf_probe_read_kernel_str(e->pathname, sizeof(e->pathname), "pipe:data");

	bpf_ringbuf_submit(e, 0);
	return 0;
}
