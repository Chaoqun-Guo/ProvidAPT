// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
	query "github.com/Chaoqun-Guo/ProvidAPT/internal/engine/graphquery"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/storage/schema"
	store "github.com/Chaoqun-Guo/ProvidAPT/internal/storage/pebblestore"
)

// ─── Schema tests ───────────────────────────────────────────

func TestNodeKey(t *testing.T) {
	key := schema.NodeKey("process", "p:1234")
	if key != "n:process:p:1234" {
		t.Errorf("NodeKey = %q", key)
	}
}

func TestEdgeKey(t *testing.T) {
	key := schema.EdgeKey(1000, "p:1", "f:100")
	if len(key) == 0 {
		t.Error("empty edge key")
	}
	if key[:2] != "e:" {
		t.Errorf("prefix = %s", key[:2])
	}
}

func TestParseNodeKey(t *testing.T) {
	typ, id, ok := schema.ParseNodeKey("n:process:p:1234")
	if !ok || typ != "process" || id != "p:1234" {
		t.Errorf("ParseNodeKey = %q, %q, %v", typ, id, ok)
	}
}

func TestEdgeTimeRange(t *testing.T) {
	start, end := schema.EdgeTimeRange(0, 1000)
	if start != "e:0000000000000000:" {
		t.Errorf("start = %q", start)
	}
	if end != "e:00000000000003e8:" {
		t.Errorf("end = %q", end)
	}
}

func TestPIDIndexKey(t *testing.T) {
	key := schema.PIDIndexKey(1337, "p:1337")
	if key != "idx:pid:1337:p:1337" {
		t.Errorf("PIDIndexKey = %q", key)
	}
}

func TestInodeIndexKey(t *testing.T) {
	key := schema.InodeIndexKey(5000, 8, 3, "f:5000:8:3")
	if key != "idx:inode:5000:8:3:f:5000:8:3" {
		t.Errorf("InodeIndexKey = %q", key)
	}
}

// ─── Store tests ────────────────────────────────────────────

func openTestStore(t *testing.T) *store.Store {
	dir, err := os.MkdirTemp("", "providapt-v2-test-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	st, err := store.Open(dir + "/pebble")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return st
}

func TestPutGetNode(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	node := &pb.Node{
		Id: "p:100", Type: "process", Label: "bash",
		Pid: 100, Comm: "bash", Uid: 1000,
	}
	if err := st.PutNode(node); err != nil {
		t.Fatalf("PutNode: %v", err)
	}
	st.Flush()

	got, err := st.GetNode("process", "p:100")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got == nil {
		t.Fatal("GetNode returned nil")
	}
	if got.Label != "bash" {
		t.Errorf("Label = %s", got.Label)
	}
	if got.Uid != 1000 {
		t.Errorf("Uid = %d", got.Uid)
	}
}

func TestPutGetEdge(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	edge := &pb.Edge{
		Id: "e:1", Source: "p:100", Target: "f:500",
		Relation: "used", TimestampNs: 1000, Count: 1,
	}
	if err := st.PutEdge(edge); err != nil {
		t.Fatalf("PutEdge: %v", err)
	}
	st.Flush()

	edges, err := st.GetEdgesBySource("p:100")
	if err != nil {
		t.Fatalf("GetEdgesBySource: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].Target != "f:500" {
		t.Errorf("Target = %s", edges[0].Target)
	}
}

func TestGetNodeByPID(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	st.PutNode(&pb.Node{Id: "p:200", Type: "process", Label: "nginx", Pid: 200})
	st.PutNode(&pb.Node{Id: "p:201", Type: "process", Label: "bash", Pid: 201})
	st.Flush()

	node, err := st.GetNodeByPID(200)
	if err != nil {
		t.Fatalf("GetNodeByPID: %v", err)
	}
	if node == nil {
		t.Fatal("node not found")
	}
	if node.Label != "nginx" {
		t.Errorf("Label = %s", node.Label)
	}
}

func TestGetNodeByInode(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	st.PutNode(&pb.Node{Id: "f:999:8:3", Type: "file", Label: "/etc/hosts", Inode: 999, DevMajor: 8, DevMinor: 3})
	st.Flush()

	node, err := st.GetNodeByInode(999)
	if err != nil {
		t.Fatalf("GetNodeByInode: %v", err)
	}
	if node == nil {
		t.Fatal("node not found")
	}
	if node.Label != "/etc/hosts" {
		t.Errorf("Label = %s", node.Label)
	}
}

func TestTimeRangeQuery(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	for i := 0; i < 5; i++ {
		ts := uint64(1000 + i*100)
		st.PutEdge(&pb.Edge{
			Source: "p:1", Target: "f:100",
			TimestampNs: ts, Count: 1,
		})
	}
	st.Flush()

	edges, err := st.GetEdgesByTimeRange(1100, 1300)
	if err != nil {
		t.Fatalf("GetEdgesByTimeRange: %v", err)
	}
	if len(edges) != 2 {
		t.Errorf("expected 2 edges in range, got %d", len(edges))
	}
}

func TestReverseEdgeIndex(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	st.PutEdge(&pb.Edge{
		Source: "p:100", Target: "f:500", TimestampNs: 1000,
	})
	st.Flush()

	edges, err := st.GetEdgesByTarget("f:500")
	if err != nil {
		t.Fatalf("GetEdgesByTarget: %v", err)
	}
	if len(edges) != 1 {
		t.Errorf("expected 1 reverse edge, got %d", len(edges))
	}
}

// ─── Query engine tests ────────────────────────────────────

func TestQueryEngine(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	st.PutNode(&pb.Node{Id: "p:300", Type: "process", Label: "curl", Pid: 300})
	st.PutNode(&pb.Node{Id: "n:5.6.7.8:443", Type: "network", Label: "5.6.7.8:443"})
	st.PutEdge(&pb.Edge{Source: "p:300", Target: "n:5.6.7.8:443", Relation: "used", TimestampNs: 1000})
	st.Flush()

	qe := query.New(st)

	detail, err := qe.GetProcessByPID(300)
	if err != nil {
		t.Fatalf("GetProcessByPID: %v", err)
	}
	if detail == nil {
		t.Fatal("process not found")
	}
	if detail.Node.Comm != "curl" {
		t.Errorf("comm = %s", detail.Node.Comm)
	}
	if len(detail.Edges) == 0 {
		t.Error("expected edges")
	}
}

func TestQueryNodeByID(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	st.PutNode(&pb.Node{Id: "p:400", Type: "process", Label: "sshd", Pid: 400})
	st.Flush()

	qe := query.New(st)
	detail, err := qe.GetNodeByID("process", "p:400")
	if err != nil {
		t.Fatalf("GetNodeByID: %v", err)
	}
	if detail == nil || detail.Node.Label != "sshd" {
		t.Errorf("got %v", detail)
	}
}

func TestTimeRangeQueryEmpty(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	qe := query.New(st)
	edges, err := qe.GetEdgesInRange(time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GetEdgesInRange: %v", err)
	}
	if len(edges) != 0 {
		t.Errorf("expected 0 edges, got %d", len(edges))
	}
}

func TestFormatNode(t *testing.T) {
	s := query.FormatNode(&pb.Node{Id: "p:1", Type: "process", Label: "init", Pid: 1})
	if s == "" {
		t.Error("empty format")
	}
	t.Logf("FormatNode: %s", s)
}

func TestFormatEdge(t *testing.T) {
	s := query.FormatEdge(&pb.Edge{Source: "p:1", Target: "f:100", Relation: "used", Count: 42})
	if s == "" {
		t.Error("empty format")
	}
	t.Logf("FormatEdge: %s", s)
}

// ─── Protobuf serialization tests ───────────────────────────

func TestProtoNodeMarshal(t *testing.T) {
	node := &pb.Node{
		Id: "p:500", Type: "process", Label: "test",
		Pid: 500, Uid: 1000, Comm: "test",
		Attrs: map[string]string{"key": "value"},
	}
	data, err := proto.Marshal(node)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded pb.Node
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Label != "test" {
		t.Errorf("label = %s", decoded.Label)
	}
	if decoded.Attrs["key"] != "value" {
		t.Errorf("attr = %s", decoded.Attrs["key"])
	}
}

func TestProtoEdgeMarshal(t *testing.T) {
	edge := &pb.Edge{
		Source: "p:1", Target: "f:100",
		Relation: "used", Count: 42,
		TimestampNs: 1000000,
	}
	data, err := proto.Marshal(edge)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded pb.Edge
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Relation != "used" {
		t.Errorf("relation = %s", decoded.Relation)
	}
}
