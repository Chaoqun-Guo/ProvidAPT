/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PROVIDAPT_H
#define __PROVIDAPT_H

/* ============================================================
 * ProvidAPT — shared definitions between kernel eBPF and userspace.
 *
 * All structures use __attribute__((packed)) for a deterministic
 * wire-format ABI across kernel versions.  The Go parser in
 * userspace/pkg/collector/ringbuf.go must match this layout exactly.
 * ============================================================ */

/* ─── Limits ───────────────────────────────────────────── */
#define TASK_COMM_LEN    16
#define PATH_MAX_LEN     256

/* ─── Device number helpers (guaranteed availability in eBPF) ─ */
#define MINORBITS        20
#define MINORMASK        ((1U << MINORBITS) - 1)

/* ─── File open flags (from <linux/fcntl.h>, not always in vmlinux.h) ─ */
#define O_RDONLY         0
#define O_WRONLY         1
#define O_RDWR           2
#define O_CREAT        0100
#define O_TRUNC       01000
#define O_APPEND      02000
#define O_EXCL         0200

/* ─── Access/error constants when kernel headers do not provide them ─── */
#ifndef MAY_EXEC
#define MAY_EXEC        0x00000001
#endif
#ifndef MAY_WRITE
#define MAY_WRITE       0x00000002
#endif
#ifndef MAY_READ
#define MAY_READ        0x00000004
#endif
#ifndef EPERM
#define EPERM           1
#endif

/* ─── Socket/protocol constants when kernel headers do not provide them ─── */
#ifndef AF_INET
#define AF_INET         2
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP     6
#endif

/* ─── Ring buffer size (bytes) ─────────────────────────── */
#define RINGBUF_SIZE     (1 << 22)    /* 4 MB */

/* ─── BPF maps max entries ─────────────────────────────── */
#define MAP_MAX_ENTRIES  65536
#define DEDUP_MAP_SIZE   65536

/* ─── Dedup time window (nanoseconds) ─────────────────── */
#define DEDUP_WINDOW_NS  100000000ULL    /* 100 ms */

/* ─── Hot path prefix hash helper ─────────────────────── */
/* Hash a string to u32 (FNV-1a) — used for hot_path map lookup */
#define HASH_SEED        2166136261U

/* ─── Event type constants (u32, not enum, for fixed ABI) ─ */
#define EV_PROCESS_FORK      1U
#define EV_PROCESS_EXEC      2U
#define EV_PROCESS_EXIT      3U
#define EV_FILE_OPEN        10U
#define EV_FILE_CREATE      11U
#define EV_FILE_MODIFY      12U
#define EV_FILE_DELETE      13U
#define EV_FILE_RENAME      14U
#define EV_NET_CONNECT      20U
#define EV_NET_ACCEPT       21U
#define EV_NET_SEND         22U
#define EV_NET_RECV         23U
#define EV_CRED_SETUID      40U
#define EV_CRED_CAPABLE     41U
/* Memory attack events */
#define EV_MEMFD_CREATE    50U   /* memfd_create — anonymous file */
#define EV_MPROTECT_RX     51U   /* mprotect RW→RX — shellcode injection */
#define EV_PIPE_WRITE      52U   /* pipe write — cross-process data flow */
#define EV_PIPE_READ       53U   /* pipe read — cross-process data flow */
/* Sampling — aggregated report from adaptive sampling */
#define EV_SAMPLE          100U
/* Defense — agent death event */
#define EV_AGENT_KILLED    200U
#define EV_FILE_DENIED     201U
/* Deception — honeytoken events */
#define EV_HONEYPOT_TRIGGER 210U   /* honeytoken file accessed */
#define EV_HONEYPOT_LIST    211U   /* honeytoken directory listed */

/* ─── Event flags ──────────────────────────────────────── */
#define EV_FLAG_NONE        0U
#define EV_FLAG_FROM_USER   (1U << 0)
#define EV_FLAG_IS_ROOT     (1U << 1)
#define EV_FLAG_EXEC_SETUID (1U << 2)

/* ─── File payload ─────────────────────────────────────── */
struct file_payload {
	__u64 inode;
	__u32 dev_major;
	__u32 dev_minor;
	__u32 mode;       /* S_IFMT file type + permissions */
	__u32 f_flags;    /* O_RDONLY / O_WRONLY / O_RDWR | O_CREAT | O_TRUNC … */
} __attribute__((packed));

/* ─── Process-fork payload ─────────────────────────────── */
struct fork_payload {
	__u32 child_pid;
} __attribute__((packed));

/* ─── Network payload ────────────────────────────────────── */
struct net_payload {
	__u32 saddr;      /* source IPv4 address      */
	__u32 daddr;      /* destination IPv4 address */
	__u16 sport;      /* source port              */
	__u16 dport;      /* destination port         */
	__u8  protocol;   /* IPPROTO_*                */
} __attribute__((packed));

/* ─── Main ring-buffer event record ──────────────────────
 *
 *   Offset  Field          Type        Bytes
 *   ──────  ─────          ────        ─────
 *        0  type           u32             4
 *        4  flags          u32             4
 *        8  timestamp_ns   u64             8
 *       16  pid            u32             4
 *       20  tid            u32             4
 *       24  ppid           u32             4
 *       28  uid            u32             4
 *       32  gid            u32             4
 *       36  payload        union    24 / 8 max
 *       60  comm           char[16]       16
 *       76  pathname       char[256]     256
 *   ──────                                    332 total
 *
 * IMPORTANT:  struct is packed — no alignment padding between gid
 * (offset 32) and the payload union that follows at offset 36.
 * The union carries a __u64 (inode) at offset 36, which is *not*
 * 8-byte aligned — this is fine on x86_64 but slightly slower.
 * --------------------------------------------------------- */
struct event {
	__u32 type;
	__u32 flags;
	__u64 timestamp_ns;

	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;

	union {
		struct file_payload file;
		struct fork_payload fork;
		struct net_payload net;
	} payload;

	/* Sampling payload (when type == EV_SAMPLE) — overlays pathname */
	__u32 sample_hook_id;     /* which hook was being sampled */
	__u32 sample_count;       /* how many occurrences were merged */

	char comm[TASK_COMM_LEN];
	char pathname[PATH_MAX_LEN];
} __attribute__((packed));

/* static_assert(sizeof(struct event) == 332, "struct event size mismatch"); */

#endif /* __PROVIDAPT_H */
