// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package syscall

// Event flag bits (matches EV_FLAG_* in kernel/include/providapt.h)
const (
	EventFlagNone       uint32 = 0
	EventFlagFromUser   uint32 = 1 << 0
	EventFlagIsRoot     uint32 = 1 << 1
	EventFlagExecSetuid uint32 = 1 << 2
)

type EventType uint32

const (
	EventProcessFork EventType = 1
	EventProcessExec EventType = 2
	EventProcessExit EventType = 3
	EventFileOpen    EventType = 10
	EventFileCreate  EventType = 11
	EventFileModify  EventType = 12
	EventFileDelete  EventType = 13
	EventFileRename  EventType = 14
	EventNetConnect  EventType = 20
	EventNetAccept   EventType = 21
	EventNetSend     EventType = 22
	EventNetRecv     EventType = 23
	EventCredSetuid  EventType = 40
	EventCredCapable EventType = 41
	EventMemfdCreate EventType = 50
	EventMprotectRX  EventType = 51
	EventPipeWrite   EventType = 52
	EventPipeRead    EventType = 53
)

// String returns a human-readable event type name.
func (et EventType) String() string {
	switch et {
	case EventProcessFork:
		return "proc_fork"
	case EventProcessExec:
		return "proc_exec"
	case EventProcessExit:
		return "proc_exit"
	case EventFileOpen:
		return "file_open"
	case EventFileCreate:
		return "file_create"
	case EventFileModify:
		return "file_modify"
	case EventFileDelete:
		return "file_delete"
	case EventFileRename:
		return "file_rename"
	case EventNetConnect:
		return "net_connect"
	case EventNetAccept:
		return "net_accept"
	case EventNetSend:
		return "net_send"
	case EventNetRecv:
		return "net_recv"
	case EventCredSetuid:
		return "cred_setuid"
	case EventCredCapable:
		return "cred_capable"
	case EventMemfdCreate:
		return "memfd_create"
	case EventMprotectRX:
		return "mprotect_rx"
	case EventPipeWrite:
		return "pipe_write"
	case EventPipeRead:
		return "pipe_read"
	default:
		return "unknown"
	}
}
