/* SPDX-License-Identifier: GPL-2.0
 *
 * ProvidAPT — eBPF helper utilities
 *
 * This file is compiled as a SEPARATE .bpf.o so the helpers can be
 * reused across programs.  The functions are marked __always_inline
 * and placed in the header-import section; they get inlined into
 * each calling BPF program at compile time.
 *
 * Usage:
 *   #include "helpers.bpf.c"    (in the .bpf.c that needs them)
 *
 * However, since BPF programs can't share text across sections,
 * the preferred pattern is to keep helpers in the SAME .c file
 * (lsm_hooks.bpf.c) and let Clang inline them within the
 * compilation unit.
 *
 * This file exists for utility functions that don't fit neatly
 * into the main hook file (e.g. generic path helpers, checksum
 * helpers, or rate-limit state machines).
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include "providapt.h"

/* ─── Extract the final path component from a NUL-terminated path ───────
 *
 * Input   /var/log/syslog
 * Output  syslog
 *
 * Used when the userspace side needs a quick basename without
 * re-parsing the full path string.
 */
__always_inline static const char *path_basename(const char *path, u32 max_len)
{
	const char *base = path;
	u32 i;

	/* Walk the entire string looking for the last '/' */
	#pragma unroll
	for (i = 0; i < max_len; i++) {
		if (path[i] == '\0')
			break;
		if (path[i] == '/')
			base = &path[i + 1];
	}
	return base;
}

/* ─── Classify file type from inode mode bits ──────────────────────────
 *
 * Returns one of:
 *   "reg"  — regular file        (S_ISREG)
 *   "dir"  — directory           (S_ISDIR)
 *   "lnk"  — symbolic link       (S_ISLNK)
 *   "sock" — socket              (S_ISOCK)
 *   "fifo" — pipe / FIFO         (S_ISFIFO)
 *   "chr"  — character device    (S_ISCHR)
 *   "blk"  — block device        (S_ISBLK)

 *
 * Not used in the hot path; provided for analysis convenience.
 */
__always_inline static const char *file_type_str(u32 mode)
{
	u32 ft = mode & S_IFMT;
	switch (ft) {
	case S_IFREG:  return "reg";
	case S_IFDIR:  return "dir";
	case S_IFLNK:  return "lnk";
	case S_IFSOCK: return "sock";
	case S_IFIFO:  return "fifo";
	case S_IFCHR:  return "chr";
	case S_IFBLK:  return "blk";
	default:       return "?";
	}
}
