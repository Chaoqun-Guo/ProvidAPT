/* SPDX-License-Identifier: GPL-2.0
 * ProvidAPT container-aware eBPF enrichment
 *
 * Captures:
 *   - Cgroup ID  via bpf_get_current_cgroup_id()
 *   - PID NS     via bpf_get_current_task()->nsproxy->pid_ns_for_children
 *
 * These identifiers are embedded in ring buffer events so that
 * userspace can map them to container names/images.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer shared with lsm_hooks */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} rb_container SEC(".maps");

/* Extended event with container context */
struct container_event {
    /* Standard fields */
    __u32 type;
    __u32 flags;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u8  comm[16];
    __u8  pathname[256];

    /* container enrichment */
    __u64 cgroup_id;
    __u64 pid_namespace_id;
};

/* pid namespace helper */
static __always_inline __u64 get_pid_ns_id(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *np = BPF_CORE_READ(task, nsproxy);
    if (!np) return 0;
    struct pid_namespace *pid_ns = BPF_CORE_READ(np, pid_ns_for_children);
    if (!pid_ns) return 0;
    return BPF_CORE_READ(pid_ns, ns.inum);
}

/* file_open hook with container enrichment */
SEC("lsm.s/file_open")
int BPF_PROG(probe_container_file_open, struct file *file)
{
    struct container_event *e;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    e = bpf_ringbuf_reserve(&rb_container, sizeof(*e), 0);
    if (!e) return 0;

    e->type = 10;  /* EV_FILE_OPEN */
    e->flags = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* container context */
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid_namespace_id = get_pid_ns_id();

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* sched_process_fork hook propagating container context */
SEC("tracepoint/sched/sched_process_fork")
int BPF_PROG(probe_container_fork, struct task_struct *parent,
             struct task_struct *child)
{
    struct container_event *e;

    e = bpf_ringbuf_reserve(&rb_container, sizeof(*e), 0);
    if (!e) return 0;

    e->type = 1;  /* EV_PROCESS_FORK */
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = BPF_CORE_READ(child, pid);
    e->ppid = BPF_CORE_READ(parent, pid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* container context inherited from parent */
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid_namespace_id = get_pid_ns_id();

    bpf_ringbuf_submit(e, 0);
    return 0;
}
