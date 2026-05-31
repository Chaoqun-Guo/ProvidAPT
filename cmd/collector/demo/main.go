// ProvidAPT v2 — Storage Layer Integration
//
// Demonstrates: Protobuf schema → RocksDB Key Schema →
// Async batch writer → Query interface
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
	query "github.com/Chaoqun-Guo/ProvidAPT/internal/engine/graphquery"
	store "github.com/Chaoqun-Guo/ProvidAPT/internal/storage/pebblestore"
)

func main() {
	fmt.Println("ProvidAPT v2 — Storage Layer Demo")
	fmt.Println("=================================")
	fmt.Println()

	// ── Open store ─────────────────────────────────────
	dir, err := os.MkdirTemp("", "providapt-v2-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	st, err := store.Open(dir + "/pebble")
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	// ── Write nodes ────────────────────────────────────
	fmt.Println("Writing nodes...")

	processNode := &pb.Node{
		Id:          "p:1337",
		Type:        "process",
		Label:       "nginx",
		Pid:         1337,
		Ppid:        1,
		Uid:         0,
		Comm:        "nginx",
		FirstSeenNs: uint64(time.Now().UnixNano()),
		Identity:    "nginx-service-account",
		MonitorLevel: 0,
		Attrs:       map[string]string{"version": "1.24", "config": "/etc/nginx/nginx.conf"},
	}
	if err := st.PutNode(processNode); err != nil {
		log.Fatalf("put process node: %v", err)
	}
	fmt.Printf("  ✓ Process node: pid=%d comm=%s\n", processNode.Pid, processNode.Comm)

	fileNode := &pb.Node{
		Id:          "f:5000:8:3",
		Type:        "file",
		Label:       "/etc/shadow",
		Inode:       5000,
		DevMajor:    8,
		DevMinor:    3,
		Mode:        0o100644,
		FirstSeenNs: uint64(time.Now().UnixNano()),
	}
	if err := st.PutNode(fileNode); err != nil {
		log.Fatalf("put file node: %v", err)
	}
	fmt.Printf("  ✓ File node: path=%s inode=%d\n", fileNode.Label, fileNode.Inode)

	networkNode := &pb.Node{
		Id:    "n:5.6.7.8:443",
		Type:  "network",
		Label: "5.6.7.8:443",
	}
	if err := st.PutNode(networkNode); err != nil {
		log.Fatalf("put network node: %v", err)
	}
	fmt.Printf("  ✓ Network node: %s\n", networkNode.Label)

	// ── Write edges ────────────────────────────────────
	fmt.Println("\nWriting edges...")

	now := uint64(time.Now().UnixNano())

	edges := []*pb.Edge{
		{Id: "e:1", Source: "p:1337", Target: "f:5000:8:3", Relation: "used", TimestampNs: now, Count: 3},
		{Id: "e:2", Source: "p:1337", Target: "n:5.6.7.8:443", Relation: "used", TimestampNs: now + 1000, Count: 1},
		{Id: "e:3", Source: "p:1337", Target: "p:1338", Relation: "wasInformedBy", TimestampNs: now + 2000, Count: 1},
	}

	for _, e := range edges {
		if err := st.PutEdge(e); err != nil {
			log.Fatalf("put edge: %v", err)
		}
	}
	fmt.Printf("  ✓ %d edges written\n", len(edges))

	// ── Flush batch ────────────────────────────────────
	if err := st.Flush(); err != nil {
		log.Fatalf("flush: %v", err)
	}
	fmt.Println("\n  ✓ Batch flushed to RocksDB")

	// ── Query by PID ───────────────────────────────────
	fmt.Println("\n─── Query by PID: 1337 ───────────────────")
	qe := query.New(st)

	detail, err := qe.GetProcessByPID(1337)
	if err != nil {
		log.Fatalf("query by pid: %v", err)
	}
	if detail != nil {
		fmt.Printf("  Node: %s\n", query.FormatNode(detail.Node))
		fmt.Printf("  Attrs: %v\n", detail.Node.Attrs)
		fmt.Printf("  Identity: %s\n", detail.Node.Identity)
		fmt.Printf("  Edges (%d):\n", len(detail.Edges))
		for _, e := range detail.Edges {
			fmt.Printf("    %s\n", query.FormatEdge(e))
		}
	}

	// ── Query by Inode ────────────────────────────────
	fmt.Println("\n─── Query by Inode: 5000 ─────────────────")
	detail2, err := qe.GetFileByInode(5000)
	if err != nil {
		log.Fatalf("query by inode: %v", err)
	}
	if detail2 != nil {
		fmt.Printf("  Node: %s\n", query.FormatNode(detail2.Node))
		fmt.Printf("  Edges (%d):\n", len(detail2.Edges))
		for _, e := range detail2.Edges {
			fmt.Printf("    %s\n", query.FormatEdge(e))
		}
	}

	// ── Time-range query ──────────────────────────────
	fmt.Println("\n─── Time-Range Query ─────────────────────")
	start := time.Unix(0, int64(now-1))
	end := time.Unix(0, int64(now+5000))

	rangeEdges, err := qe.GetEdgesInRange(start, end)
	if err != nil {
		log.Fatalf("time-range query: %v", err)
	}
	fmt.Printf("  Edges in range: %d\n", len(rangeEdges))

	// ── Stats ──────────────────────────────────────────
	fmt.Println("\n─── Store Statistics ─────────────────────")
	stats := st.Stats()
	fmt.Printf("  Nodes written:     %d\n", stats["nodes_written"])
	fmt.Printf("  Edges written:     %d\n", stats["edges_written"])
	fmt.Printf("  Batches committed: %d\n", stats["batches_committed"])
	fmt.Printf("  Bytes written:     %d\n", stats["bytes_written"])
	fmt.Printf("  Disk usage:        %d bytes\n", stats["disk_usage_bytes"])

	fmt.Println("\nProvidAPT v2 storage layer demo completed.")
}
