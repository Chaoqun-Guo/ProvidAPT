// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package graphquery

import (
	"errors"
	"testing"
	"time"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// ─── Mock store ──────────────────────────────────────────────

type mockStore struct {
	nodes      map[string]*pb.Node // key = "type:id"
	pidIdx     map[uint32]string   // pid → "type:id"
	inodeIdx   map[uint64]string   // inode → "type:id"
	edgesBySrc map[string][]*pb.Edge
	edgesByTgt map[string][]*pb.Edge
	timeEdges  []*pb.Edge
	err        error // injected error; if set all methods return it
}

func (m *mockStore) GetNodeByPID(pid uint32) (*pb.Node, error) {
	if m.err != nil {
		return nil, m.err
	}
	key, ok := m.pidIdx[pid]
	if !ok {
		return nil, nil
	}
	return m.nodes[key], nil
}

func (m *mockStore) GetNodeByInode(inode uint64) (*pb.Node, error) {
	if m.err != nil {
		return nil, m.err
	}
	key, ok := m.inodeIdx[inode]
	if !ok {
		return nil, nil
	}
	return m.nodes[key], nil
}

func (m *mockStore) GetNode(nodeType, nodeID string) (*pb.Node, error) {
	if m.err != nil {
		return nil, m.err
	}
	n, ok := m.nodes[nodeType+":"+nodeID]
	if !ok {
		return nil, nil
	}
	return n, nil
}

func (m *mockStore) GetEdgesBySource(source string) ([]*pb.Edge, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.edgesBySrc[source], nil
}

func (m *mockStore) GetEdgesByTarget(target string) ([]*pb.Edge, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.edgesByTgt[target], nil
}

func (m *mockStore) GetEdgesByTimeRange(startNs, endNs uint64) ([]*pb.Edge, error) {
	if m.err != nil {
		return nil, m.err
	}
	var result []*pb.Edge
	for _, e := range m.timeEdges {
		if e.TimestampNs >= startNs && e.TimestampNs < endNs {
			result = append(result, e)
		}
	}
	return result, nil
}

// ─── Test fixtures ────────────────────────────────────────────

func newProcessNode(id, label string, pid uint32) *pb.Node {
	return &pb.Node{
		Id:    id,
		Type:  "process",
		Label: label,
		Pid:   pid,
	}
}

func newFileNode(id, label string, inode uint64) *pb.Node {
	return &pb.Node{
		Id:    id,
		Type:  "file",
		Label: label,
		Inode: inode,
	}
}

func newEdge(src, tgt, rel string, ts uint64) *pb.Edge {
	return &pb.Edge{
		Source:      src,
		Target:      tgt,
		Relation:    rel,
		TimestampNs: ts,
		Count:       1,
	}
}

// ─── Tests ────────────────────────────────────────────────────

func TestGetProcessByPID_Found(t *testing.T) {
	m := &mockStore{
		nodes: map[string]*pb.Node{
			"process:p:1001": newProcessNode("p:1001", "bash", 1001),
		},
		pidIdx: map[uint32]string{
			1001: "process:p:1001",
		},
		edgesBySrc: map[string][]*pb.Edge{
			"p:1001": {newEdge("p:1001", "f:100", "used", 1000)},
		},
		edgesByTgt: map[string][]*pb.Edge{
			"p:1001": {newEdge("p:999", "p:1001", "wasInformedBy", 1000)},
		},
	}

	qe := New(m)
	detail, err := qe.GetProcessByPID(1001)
	if err != nil {
		t.Fatal(err)
	}
	if detail == nil {
		t.Fatal("expected non-nil detail")
	}
	if detail.Node.Label != "bash" {
		t.Errorf("label = %q, want %q", detail.Node.Label, "bash")
	}
	if len(detail.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(detail.Edges))
	}
}

func TestGetProcessByPID_NotFound(t *testing.T) {
	m := &mockStore{
		pidIdx: map[uint32]string{},
	}
	qe := New(m)
	detail, err := qe.GetProcessByPID(9999)
	if err != nil {
		t.Fatal(err)
	}
	if detail != nil {
		t.Fatal("expected nil for unknown PID")
	}
}

func TestGetProcessByPID_StoreError(t *testing.T) {
	m := &mockStore{err: errors.New("store error")}
	qe := New(m)
	_, err := qe.GetProcessByPID(1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetFileByInode_Found(t *testing.T) {
	m := &mockStore{
		nodes: map[string]*pb.Node{
			"file:f:50:1000": newFileNode("f:50:1000", "/etc/hosts", 50),
		},
		inodeIdx: map[uint64]string{
			50: "file:f:50:1000",
		},
	}

	qe := New(m)
	detail, err := qe.GetFileByInode(50)
	if err != nil {
		t.Fatal(err)
	}
	if detail == nil {
		t.Fatal("expected non-nil detail")
	}
	if detail.Node.Label != "/etc/hosts" {
		t.Errorf("label = %q, want %q", detail.Node.Label, "/etc/hosts")
	}
}

func TestGetFileByInode_NotFound(t *testing.T) {
	m := &mockStore{inodeIdx: map[uint64]string{}}
	qe := New(m)
	detail, err := qe.GetFileByInode(999)
	if err != nil {
		t.Fatal(err)
	}
	if detail != nil {
		t.Fatal("expected nil for unknown inode")
	}
}

func TestGetNodeByID_Found(t *testing.T) {
	m := &mockStore{
		nodes: map[string]*pb.Node{
			"process:p:42": newProcessNode("p:42", "sshd", 42),
		},
	}

	qe := New(m)
	detail, err := qe.GetNodeByID("process", "p:42")
	if err != nil {
		t.Fatal(err)
	}
	if detail == nil {
		t.Fatal("expected non-nil detail")
	}
	if detail.Node.Label != "sshd" {
		t.Errorf("label = %q, want %q", detail.Node.Label, "sshd")
	}
}

func TestGetNodeByID_NotFound(t *testing.T) {
	m := &mockStore{nodes: map[string]*pb.Node{}}
	qe := New(m)
	detail, err := qe.GetNodeByID("file", "f:999")
	if err != nil {
		t.Fatal(err)
	}
	if detail != nil {
		t.Fatal("expected nil for unknown node")
	}
}

func TestGetEdgesInRange(t *testing.T) {
	t1 := uint64(1000)
	t2 := uint64(2000)
	t3 := uint64(3000)

	m := &mockStore{
		timeEdges: []*pb.Edge{
			newEdge("p:1", "f:10", "used", t1),
			newEdge("p:1", "f:20", "used", t2),
			newEdge("p:2", "f:30", "used", t3),
		},
	}

	qe := New(m)
	// Query range [1500, 3500) → should match t2 and t3
	edges, err := qe.GetEdgesInRange(
		time.Unix(0, int64(1500)),
		time.Unix(0, int64(3500)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(edges))
	}
}

func TestGetEdgesInRange_Empty(t *testing.T) {
	m := &mockStore{timeEdges: nil}
	qe := New(m)
	edges, err := qe.GetEdgesInRange(time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 0 {
		t.Fatalf("expected 0 edges, got %d", len(edges))
	}
}

// ─── Format helpers ───────────────────────────────────────────

func TestFormatNode(t *testing.T) {
	n := newProcessNode("p:100", "bash", 100)
	n.Inode = 0
	s := FormatNode(n)
	if s == "" || s == "(nil)" {
		t.Errorf("unexpected FormatNode output: %q", s)
	}
}

func TestFormatNode_Nil(t *testing.T) {
	if s := FormatNode(nil); s != "(nil)" {
		t.Errorf("expected %q, got %q", "(nil)", s)
	}
}

func TestFormatEdge(t *testing.T) {
	e := newEdge("p:1", "f:10", "used", 1000)
	e.Count = 5
	s := FormatEdge(e)
	if s == "" {
		t.Error("expected non-empty edge string")
	}
}

// ─── Error propagation ────────────────────────────────────────

func TestQueryEngine_AllMethodsPropagateError(t *testing.T) {
	m := &mockStore{err: errors.New("disk error")}
	qe := New(m)

	cases := []struct {
		name string
		fn   func() error
	}{
		{"GetProcessByPID", func() error { _, err := qe.GetProcessByPID(1); return err }},
		{"GetFileByInode", func() error { _, err := qe.GetFileByInode(1); return err }},
		{"GetNodeByID", func() error { _, err := qe.GetNodeByID("p", "x"); return err }},
		{"GetEdgesInRange", func() error { _, err := qe.GetEdgesInRange(time.Time{}, time.Time{}); return err }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestNilNodeReturnsNil(t *testing.T) {
	// When store.GetNodeByPID returns (nil, nil), graphquery should return (nil, nil).
	m := &mockStore{pidIdx: map[uint32]string{1: "process:p:1"}} // pidIdx has entry, but nodes map is empty
	qe := New(m)
	detail, err := qe.GetProcessByPID(1)
	if err != nil {
		t.Fatal(err)
	}
	if detail != nil {
		t.Fatal("expected nil detail when store returns nil node")
	}
}
