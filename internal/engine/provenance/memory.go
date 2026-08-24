// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"fmt"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

// addMemoryEvent handles memory-related events (memfd_create,
// mprotect RW→RX, pipe data flow).  These create anonymous-file
// or memory-region entity nodes linked to the acting process.
func (g *Graph) addMemoryEvent(evt *collector.Event, ts time.Time) {
	procID := nodeID("p", evt.PID)
	proc := g.getOrCreateNode(procID, ProvActivity, SubProcess,
		evt.Comm, ts)
	proc.upsertAttr("pid", evt.PID)
	proc.upsertAttr("uid", evt.UID)
	proc.touch(ts)
	proc.upsertAttr("memory_op", evt.Type.String())

	var entityID string
	var subtype string
	var label string

	switch evt.Type {
	case syscall.EventMemfdCreate:
		entityID = nodeID("memfd", evt.PID, evt.TimestampNS)
		subtype = "file"
		label = evt.Pathname
		if label == "" {
			label = "anonymous"
		}
		proc.upsertAttr("fileless", true)

	case syscall.EventMprotectRX:
		entityID = nodeID("rx", evt.Inode, evt.PID)
		subtype = "memory"
		label = fmt.Sprintf("rw→rx @0x%x", evt.Inode)
		proc.upsertAttr("shellcode", true)

	case syscall.EventPipeWrite:
		entityID = nodeID("pipe", evt.PID, evt.TimestampNS)
		subtype = "pipe"
		label = "pipe:write"
		proc.upsertAttr("pipe_writer", true)

	case syscall.EventPipeRead:
		entityID = nodeID("pipe", evt.PID, evt.TimestampNS)
		subtype = "pipe"
		label = "pipe:read"
		proc.upsertAttr("pipe_reader", true)
	}

	memNode := g.getOrCreateNode(entityID, ProvEntity, subtype, label, ts)
	memNode.upsertAttr("event", evt.Type.String())
	memNode.upsertAttr("addr", evt.Inode)
	memNode.touch(ts)

	g.addEdge(ProvUsed, procID, entityID, ts, map[string]interface{}{
		"event": evt.Type.String(),
		"flags": evt.FFlags,
	})
}
