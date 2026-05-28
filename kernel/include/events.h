/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EVENTS_H
#define __EVENTS_H

/* Event flag bits */
#define EVENT_FLAG_IS_ROOT       (1 << 0)
#define EVENT_FLAG_FROM_USER     (1 << 1)
#define EVENT_FLAG_EXEC_SETUID   (1 << 2)
#define EVENT_FLAG_FILE_CREATED  (1 << 3)
#define EVENT_FLAG_NET_INBOUND   (1 << 4)

#endif /* __EVENTS_H */
