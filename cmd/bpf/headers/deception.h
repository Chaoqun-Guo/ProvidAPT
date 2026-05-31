/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PROVIDAPT_DECEPTION_H
#define __PROVIDAPT_DECEPTION_H

/* ============================================================
 * ProvidAPT Deception Module — honeytoken event types
 * ============================================================ */

/* Honeytoken trigger event */
#define EV_HONEYPOT_TRIGGER  210U   /* honeytoken file accessed */
#define EV_HONEYPOT_LIST     211U   /* honeytoken directory listed */

/* Honeytoken flag bits (stored in taint_map or honeytoken_map value) */
#define HONEYPOT_ACTIVE      (1U << 0)  /* honeytoken injection active */
#define HONEYPOT_TRIGGERED   (1U << 1)  /* honeytoken was accessed */
#define HONEYPOT_TRIPWIRE    (1U << 2)  /* file is a tripwire (immediate freeze) */

/* Honeytoken map structure */
struct honeytoken_key {
	__u32  path_hash;    /* FNV-1a hash of honeytoken full path */
} __attribute__((packed));

struct honeytoken_val {
	__u32  flags;        /* HONEYPOT_ACTIVE | HONEYPOT_TRIPWIRE */
	__u32  pid;          /* PID that triggered (0 = not triggered) */
	__u64  triggered_at; /* timestamp when triggered */
} __attribute__((packed));

/* Honeypot trigger payload (sent via rb_defense ring buffer) */
struct honeypot_trigger {
	__u32  trigger_type;  /* 1=open, 2=stat, 3=getdents */
	__u32  path_hash;     /* hash of the matched honeytoken path */
	__u32  triggered_by;  /* PID that triggered the honeytoken */
} __attribute__((packed));

#endif /* __PROVIDAPT_DECEPTION_H */
