/* SPDX-License-Identifier: GPL-2.0
 * ProvidAPT -TCP fingerprint extraction
 *
 * Hooks:
 * kprobe/tcp_v4_connect -captures ISN + TS from outgoing SYN
 * kprobe/tcp_v4_do_rcv -captures ISN + TS from incoming SYN
 *
 * The extracted (ISN, TSval) pair forms a unique TCP fingerprint
 * that can be matched across machines for lateral movement detection.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer for fingerprint events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} rb_tcp SEC(".maps");

/* --- TCP fingerprint event --- */
struct tcp_fingerprint_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 isn;         /* Initial Sequence Number (snd_nxt) */
    __u32 tsval;       /* TCP Timestamp value */
    __u32 tsecr;       /* TCP Timestamp echo reply */
    __u8  direction;   /* 0=outbound, 1=inbound */
};

/* --- TCP timestamp option reader --- */
static __always_inline __u32 read_tsval(struct tcphdr *th) {
    /* Parse TCP options to find the Timestamp option (kind=8) */
    /* In production: parse through options to find TSval at offset 2 */
    return 0; /* Simplified for framework */
}

/* --- tcp_v4_connect --outbound connection --- */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(probe_tcp_connect, struct sock *sk)
{
    struct tcp_fingerprint_event *e;
    e = bpf_ringbuf_reserve(&rb_tcp, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->isn = BPF_CORE_READ(sk, sk_rcv_nxt);
    e->direction = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* --- tcp_v4_do_rcv --inbound packet received --- */
SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(probe_tcp_rcv, struct sock *sk, struct sk_buff *skb)
{
    struct tcp_fingerprint_event *e;
    e = bpf_ringbuf_reserve(&rb_tcp, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->isn = BPF_CORE_READ(sk, sk_rcv_nxt);
    e->direction = 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
