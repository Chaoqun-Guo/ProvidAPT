/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TAINT_H
#define __TAINT_H

/* ═══════════════════════════════════════════════════════════════
 * Taint flags — per-process tags set by eBPF programs when a
 * process exhibits behaviour that warrants closer monitoring.
 *
 * A process with any taint flag gets DETAIL_FULL event recording.
 * Taint propagates from parent to child on fork (TAINT_PARENT).
 * ═══════════════════════════════════════════════════════════════ */

#define TAINT_NONE        0U
#define TAINT_NET_CONNECT (1U << 0)  /* connected to external IP */
#define TAINT_FILE_WRITE  (1U << 1)  /* modified /etc, /root, /home */
#define TAINT_SETUID      (1U << 2)  /* executed with setuid */
#define TAINT_PARENT      (1U << 3)  /* taint inherited from parent */
#define TAINT_HONEYPOT    (1U << 4)  /* honeytoken file accessed — confirmed malicious */

/* ─── Event detail levels ──────────────────────────────────── */
enum detail_level {
	DETAIL_CORE   = 0,  /* only fork + exec events           */
	DETAIL_NORMAL = 1,  /* + file_open, socket_connect       */
	DETAIL_FULL   = 2,  /* + file_permission, fine-grained   */
};

/* ─── Sampling thresholds ──────────────────────────────────── */
#define SAMPLE_THRESHOLD     1000U           /* report after 1000 hits */
#define SAMPLE_INTERVAL_NS   1000000000ULL   /* …or at least 1 sec    */

#endif /* __TAINT_H */
