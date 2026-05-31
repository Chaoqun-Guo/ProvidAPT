/* SPDX-License-Identifier: GPL-2.0
 *
 * ProvidAPT — kernel-side dedup and hot-path bypass
 *
 * Provides:
 *   1. dedup_map — frequency limits identical operations within
 *      DEDUP_WINDOW_NS (100ms).  Repeated events only increment
 *      a counter instead of writing to the ring buffer.
 *
 *   2. hot_paths — user-updatable set of high-interest path
 *      prefixes.  Events matching these paths bypass dedup and
 *      are always reported with full detail.
 *
 * These maps are populated by userspace at runtime via the
 * control package (userspace/pkg/control/).
 */

/* ── Dedup map — kernel-side frequency limiting ───────────
 * Key:   (pid << 32) | (event_type << 16) | (inode & 0xFFFF)
 * Value: [31:0]  accumulated count
 *        [63:32] last event timestamp (ns)
 *
 * If the same (PID, event_type, target inode) repeats within
 * DEDUP_WINDOW_NS, only the counter is incremented — no ring
 * buffer write occurs, saving CPU and storage.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, DEDUP_MAP_SIZE);
	__type(key, u64);
	__type(value, u64);
} dedup_map SEC(".maps");

/* ── Hot paths map — high-interest paths that bypass dedup ─
 * Populated by userspace at runtime via the control package.
 * Key:   FNV-1a hash of path prefix (lower 32 bits)
 * Value: 1 (non-zero = bypass dedup, always report)
 *
 * Example entries written by userspace:
 *   hash("/etc")  → 1    # Always report /etc/ accesses
 *   hash("/root") → 1    # Always report /root/ accesses
 *   hash("/tmp")  → 1    # Always report /tmp/ accesses
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, u32);
} hot_paths SEC(".maps");

/* ── fnv1a_32 — hash a string to u32 for hot_path map lookup ── */
static __always_inline u32 fnv1a_32(const char *str, u32 max_len) {
	u32 h = HASH_SEED;
#pragma unroll
	for (u32 i = 0; i < max_len; i++) {
		char c;
		bpf_probe_read_kernel(&c, 1, &str[i]);
		if (c == 0) break;
		h ^= (u32)(unsigned char)c;
		h *= 16777619U;
	}
	return h;
}

/* ── is_hot_path — check if a path matches a high-interest prefix ─ */
static __always_inline bool is_hot_path(const char *path, u32 max_len) {
	u32 hash = fnv1a_32(path, max_len);
	return bpf_map_lookup_elem(&hot_paths, &hash) != NULL;
}

/* ── dedup_key — build dedup map key from PID, event type, inode ── */
static __always_inline u64 dedup_key_fn(u32 pid, u32 event_type, u64 inode) {
	return ((u64)pid << 32) | ((u64)event_type << 16) | (inode & 0xFFFF);
}

/* ── try_dedup — attempt to dedup an event.
 *
 * Returns true if the event was merged (skip ring buffer write).
 * For hot paths, always returns false (force full reporting).
 *
 * Call this at the beginning of each LSM hook that should be
 * frequency-limited (file_open, file_permission, etc.).
 */
static __always_inline bool try_dedup(u32 pid, u32 event_type,
				       u64 inode, const char *path,
				       u32 path_len) {
	/* Hot paths always bypass dedup */
	if (path && path_len > 0 && is_hot_path(path, path_len))
		return false;

	u64 key = dedup_key_fn(pid, event_type, inode);
	u64 *entry = bpf_map_lookup_elem(&dedup_map, &key);
	u64 now = bpf_ktime_get_ns();

	if (entry) {
		u32 count = (u32)(*entry & 0xFFFFFFFF);
		u64 last  = (*entry >> 32);

		if ((now - last) < DEDUP_WINDOW_NS) {
			/* Within 100ms window — merge */
			count++;
			u64 new_val = ((u64)now << 32) | count;
			bpf_map_update_elem(&dedup_map, &key, &new_val,
					    BPF_ANY);
			return true;  /* merged — skip ring buffer */
		}
		/* Outside window — reset counter and let through */
	}

	/* First occurrence or window expired — record and report */
	u64 init = ((u64)now << 32) | 1;
	bpf_map_update_elem(&dedup_map, &key, &init, BPF_ANY);
	return false;  /* not merged — write to ring buffer */
}
