package collector

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

const normalizedEventSchemaVersion = 1

type NormalizedEvent struct {
	SchemaVersion int                    `json:"schema_version"`
	Type          string                 `json:"type"`
	TypeID        uint32                 `json:"type_id"`
	Flags         uint32                 `json:"flags,omitempty"`
	TimestampNS   uint64                 `json:"timestamp_ns"`
	Process       NormalizedProcess      `json:"process"`
	Payload       map[string]interface{} `json:"payload,omitempty"`
	Enrich        NormalizedEnrich       `json:"enrich,omitempty"`
	Raw           NormalizedRaw          `json:"raw,omitempty"`
}

type NormalizedProcess struct {
	PID  uint32 `json:"pid"`
	TID  uint32 `json:"tid,omitempty"`
	PPID uint32 `json:"ppid,omitempty"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Comm string `json:"comm,omitempty"`
}

type NormalizedEnrich struct {
	ExePath string `json:"exe_path,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
}

type NormalizedRaw struct {
	PayloadKind  string `json:"payload_kind,omitempty"`
	SampleHookID uint32 `json:"sample_hook_id,omitempty"`
	SampleCount  uint32 `json:"sample_count,omitempty"`
}

func NormalizeEvent(evt *Event) NormalizedEvent {
	if evt == nil {
		return NormalizedEvent{SchemaVersion: normalizedEventSchemaVersion}
	}
	out := NormalizedEvent{
		SchemaVersion: normalizedEventSchemaVersion,
		Type:          evt.Type.String(),
		TypeID:        uint32(evt.Type),
		Flags:         evt.Flags,
		TimestampNS:   evt.TimestampNS,
		Process: NormalizedProcess{
			PID:  evt.PID,
			TID:  evt.TID,
			PPID: evt.PPID,
			UID:  evt.UID,
			GID:  evt.GID,
			Comm: evt.Comm,
		},
		Enrich: NormalizedEnrich{
			ExePath: evt.ExePath,
			Cmdline: evt.Cmdline,
		},
		Raw: NormalizedRaw{
			SampleHookID: evt.SampleHookID,
			SampleCount:  evt.SampleCount,
		},
	}

	switch evt.Type {
	case syscall.EventProcessFork:
		out.Raw.PayloadKind = "fork"
		out.Payload = map[string]interface{}{"child_pid": evt.ChildPID}
	case syscall.EventProcessExec:
		out.Raw.PayloadKind = "exec"
		out.Payload = filePayload(evt)
	case syscall.EventFileOpen, syscall.EventFileCreate, syscall.EventFileModify, syscall.EventFileDelete, syscall.EventFileRename:
		out.Raw.PayloadKind = "file"
		out.Payload = filePayload(evt)
	case syscall.EventNetConnect, syscall.EventNetAccept, syscall.EventNetSend, syscall.EventNetRecv:
		out.Raw.PayloadKind = "network"
		out.Payload = map[string]interface{}{
			"saddr":    evt.Saddr,
			"daddr":    evt.Daddr,
			"sport":    evt.Sport,
			"dport":    evt.Dport,
			"protocol": evt.Protocol,
		}
	case syscall.EventMemfdCreate, syscall.EventMprotectRX, syscall.EventPipeWrite, syscall.EventPipeRead:
		out.Raw.PayloadKind = "memory"
		out.Payload = filePayload(evt)
	default:
		if evt.SampleHookID != 0 || evt.SampleCount != 0 {
			out.Raw.PayloadKind = "sample"
		} else {
			out.Raw.PayloadKind = "unknown"
		}
	}
	return out
}

func filePayload(evt *Event) map[string]interface{} {
	payload := map[string]interface{}{
		"pathname": evt.Pathname,
		"inode":    evt.Inode,
	}
	if evt.DevMajor != 0 || evt.DevMinor != 0 {
		payload["dev_major"] = evt.DevMajor
		payload["dev_minor"] = evt.DevMinor
		payload["device"] = fmt.Sprintf("%d:%d", evt.DevMajor, evt.DevMinor)
	}
	if evt.Mode != 0 {
		payload["mode"] = evt.Mode
	}
	if evt.FFlags != 0 {
		payload["f_flags"] = evt.FFlags
	}
	return payload
}

func EventFromNormalized(norm NormalizedEvent) *Event {
	evt := &Event{
		Type:         syscall.EventType(norm.TypeID),
		Flags:        norm.Flags,
		TimestampNS:  norm.TimestampNS,
		PID:          norm.Process.PID,
		TID:          norm.Process.TID,
		PPID:         norm.Process.PPID,
		UID:          norm.Process.UID,
		GID:          norm.Process.GID,
		Comm:         norm.Process.Comm,
		ExePath:      norm.Enrich.ExePath,
		Cmdline:      norm.Enrich.Cmdline,
		SampleHookID: norm.Raw.SampleHookID,
		SampleCount:  norm.Raw.SampleCount,
	}
	if norm.Payload == nil {
		return evt
	}

	evt.Pathname = stringValue(norm.Payload["pathname"])
	evt.Inode = uint64Value(norm.Payload["inode"])
	evt.DevMajor = uint32Value(norm.Payload["dev_major"])
	evt.DevMinor = uint32Value(norm.Payload["dev_minor"])
	evt.Mode = uint32Value(norm.Payload["mode"])
	evt.FFlags = uint32Value(norm.Payload["f_flags"])
	evt.ChildPID = uint32Value(norm.Payload["child_pid"])
	evt.Saddr = uint32Value(norm.Payload["saddr"])
	evt.Daddr = uint32Value(norm.Payload["daddr"])
	evt.Sport = uint16Value(norm.Payload["sport"])
	evt.Dport = uint16Value(norm.Payload["dport"])
	evt.Protocol = uint8Value(norm.Payload["protocol"])
	return evt
}

func ParseStoredEventJSON(data []byte) (*Event, error) {
	var legacy Event
	if err := json.Unmarshal(data, &legacy); err == nil && (legacy.Type != 0 || legacy.PID != 0 || legacy.Comm != "") {
		return &legacy, nil
	}
	var norm NormalizedEvent
	if err := json.Unmarshal(data, &norm); err != nil {
		return nil, err
	}
	if norm.SchemaVersion == 0 && norm.TypeID == 0 && norm.Type == "" {
		return nil, fmt.Errorf("not a recognized event record")
	}
	return EventFromNormalized(norm), nil
}

func stringValue(value interface{}) string {
	if v, ok := value.(string); ok {
		return v
	}
	return ""
}

func uint64Value(value interface{}) uint64 {
	switch v := value.(type) {
	case float64:
		if v >= 0 && v <= math.MaxUint64 {
			return uint64(v)
		}
	case uint64:
		return v
	case uint32:
		return uint64(v)
	case int:
		if v >= 0 {
			return uint64(v)
		}
	case json.Number:
		n, _ := v.Int64()
		if n >= 0 {
			return uint64(n)
		}
	}
	return 0
}

func uint32Value(value interface{}) uint32 {
	v := uint64Value(value)
	if v > math.MaxUint32 {
		return 0
	}
	return uint32(v)
}

func uint16Value(value interface{}) uint16 {
	v := uint64Value(value)
	if v > math.MaxUint16 {
		return 0
	}
	return uint16(v)
}

func uint8Value(value interface{}) uint8 {
	v := uint64Value(value)
	if v > math.MaxUint8 {
		return 0
	}
	return uint8(v)
}
