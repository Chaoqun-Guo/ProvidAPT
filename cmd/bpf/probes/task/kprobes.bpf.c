/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "providapt.h"
#include "events.h"

char LICENSE[] SEC("license") = "GPL";

/* ─────────────────────────────────────────────
 * kprobes — capture events not covered by LSM hooks
 * Use as fallback when no LSM/tracepoint alternative exists.
 * Attach via: bpftool kprobe attach <func> <prog>
 * ───────────────────────────────────────────── */

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(probe_do_unlinkat, int dfd, struct filename *name)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_FILE_UNLINK;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
				  BPF_CORE_READ(name, name));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Security capability check — useful for privilege escalation detection */
SEC("kprobe/security_capable")
int BPF_KPROBE(probe_security_capable, const struct cred *cred,
	       struct user_namespace *ns, int cap, int opts)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_LSM_CAPABLE;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
