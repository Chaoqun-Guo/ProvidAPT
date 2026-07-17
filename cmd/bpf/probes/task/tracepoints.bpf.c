/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "providapt.h"
#include "events.h"

char LICENSE[] SEC("license") = "GPL";

/* ─────────────────────────────────────────────
 * Tracepoints — complement LSM hooks for syscall-level detail
 * Attach via: bpftool raw_tracepoint attach <tracepoint> <prog>
 * ───────────────────────────────────────────── */

SEC("tp/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
	/* Userspace triggers exec events via the LSM bprm_check hook.
	 * This tracepoint is kept as an optional argv enrichment point:
	 *   const char **argv = (const char **)ctx->args[1]; */
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx)
{
	/* The file_open LSM hook covers open events. This tracepoint remains
	 * available for optional flag enrichment (O_CREAT, O_WRONLY, etc.). */
	return 0;
}

/* Named tracepoint — new process starts (raw_syscalls style) */
SEC("raw_tp/sched_process_fork")
int BPF_PROG(raw_tp_sched_process_fork, struct task_struct *parent, struct task_struct *child)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_PROCESS_FORK;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = BPF_CORE_READ(parent, pid);
	e->tid = 0;
	e->ppid = BPF_CORE_READ(parent, real_parent, pid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	e->proc.child_pid = BPF_CORE_READ(child, pid);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
