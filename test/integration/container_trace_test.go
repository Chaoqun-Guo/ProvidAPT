//go:build integration

package integration

import (
	"strings"
	"testing"

	cli "github.com/Chaoqun-Guo/ProvidAPT/cmd/cli/trace"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/container"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/container"
)

// ─── Container monitor tests ────────────────────────────────

func TestNewMonitor(t *testing.T) {
	m := container.New()
	if m == nil {
		t.Fatal("New returned nil")
	}
}

func TestMonitorStartStop(t *testing.T) {
	m := container.New()
	m.Start()
	m.Stop()
}

func TestLookupOrEnqueue(t *testing.T) {
	m := container.New()
	info := m.LookupOrEnqueue(12345)
	if info != nil {
		t.Log("info returned immediately (unlikely)")
	} else {
		t.Log("enqueued for async resolution (expected)")
	}
}

func TestStats(t *testing.T) {
	m := container.New()
	stats := m.Stats()
	if stats["resolved_containers"] != 0 {
		t.Errorf("containers = %d", stats["resolved_containers"])
	}
}

func TestResolveProcCgroup(t *testing.T) {
	m := container.New()
	// This reads /proc/self/cgroup which exists on container hosts
	info := m.scanProc(12345678)
	if info == nil {
		t.Log("no container cgroup found (expected on bare metal)")
	} else {
		t.Logf("found container: %s (%s)", info.ContainerID, info.Orchestrator)
	}
}

func TestToProto(t *testing.T) {
	ri := &container.ResolvedInfo{
		CgroupID:     1000,
		ContainerID:  "abc123",
		Name:         "web-server",
		Orchestrator: "docker",
	}
	pb := ri.ToProto()
	if pb.ContainerId != "abc123" {
		t.Errorf("ContainerId = %s", pb.ContainerId)
	}
	if pb.Orchestrator != "docker" {
		t.Errorf("Orchestrator = %s", pb.Orchestrator)
	}
}

func TestListContainers(t *testing.T) {
	m := container.New()
	list := m.ListContainers()
	t.Logf("containers: %d", len(list))
}

// ─── CLI trace tests ────────────────────────────────────────

func TestDefaultTraceRequest(t *testing.T) {
	req := cli.DefaultTraceRequest()
	if req.Depth != 10 {
		t.Errorf("depth = %d", req.Depth)
	}
	if req.Format != "text" {
		t.Errorf("format = %s", req.Format)
	}
}

func TestMatchContainer(t *testing.T) {
	req := &cli.TraceRequest{Container: "web"}
	if !req.MatchContainer("abc", "web-server", "nginx:latest", "docker") {
		t.Error("should match web-server")
	}
	if req.MatchContainer("abc", "db-server", "mysql:8", "docker") {
		t.Error("should not match db-server")
	}
}

func TestMatchImage(t *testing.T) {
	req := &cli.TraceRequest{Image: "nginx"}
	if !req.MatchContainer("abc", "web", "nginx:latest", "docker") {
		t.Error("should match nginx image")
	}
	if req.MatchContainer("abc", "web", "httpd:latest", "docker") {
		t.Error("should not match httpd")
	}
}

func TestMatchOrchestrator(t *testing.T) {
	req := &cli.TraceRequest{Orchestrator: "k8s"}
	if !req.MatchContainer("abc", "pod", "nginx:latest", "k8s") {
		t.Error("should match k8s")
	}
	if req.MatchContainer("abc", "web", "nginx:latest", "docker") {
		t.Error("should not match docker")
	}
}

func TestBuildTraceFromEvents(t *testing.T) {
	req := cli.DefaultTraceRequest()
	events := []cli.TraceNode{
		{PID: 1, Comm: "systemd", Action: "init", Depth: 0},
		{PID: 100, Comm: "nginx", Action: "fork", ContainerName: "web-server", Depth: 1},
		{PID: 101, Comm: "bash", Action: "exec", ContainerName: "web-server", Depth: 2},
		{PID: 102, Comm: "curl", Action: "connect", ContainerName: "web-server", Depth: 3},
	}

	result := cli.BuildTraceFromEvents(events, *req)
	if result.Total != 4 {
		t.Errorf("total = %d", result.Total)
	}
}

func TestBuildTraceWithContainerFilter(t *testing.T) {
	req := &cli.TraceRequest{Container: "web", Depth: 10}
	events := []cli.TraceNode{
		{PID: 1, Comm: "systemd", ContainerName: "", Depth: 0},
		{PID: 100, Comm: "nginx", ContainerName: "web-server", Depth: 1},
		{PID: 200, Comm: "mysql", ContainerName: "db-server", Depth: 1},
		{PID: 101, Comm: "bash", ContainerName: "web-server", Depth: 2},
	}

	result := cli.BuildTraceFromEvents(events, *req)
	if result.Total != 2 {
		t.Errorf("expected 2 web-server events, got %d", result.Total)
	}
}

func TestFormatText(t *testing.T) {
	result := &cli.TraceResult{
		Request: cli.TraceRequest{Container: "web"},
		Chain: []cli.TraceNode{
			{PID: 100, Comm: "nginx", Action: "fork", ContainerName: "web-server", Depth: 0},
			{PID: 101, Comm: "bash", Action: "exec", ContainerName: "web-server", Depth: 1},
		},
		Total: 2,
	}
	text := result.FormatText()
	if !strings.Contains(text, "nginx") {
		t.Errorf("format: %s", text)
	}
	if !strings.Contains(text, "web-server") {
		t.Errorf("missing container: %s", text)
	}
	t.Logf("Trace:\n%s", text)
}

// ─── Protobuf tests ─────────────────────────────────────────

func TestContainerInfoProto(t *testing.T) {
	ci := &containerpb.ContainerInfo{
		CgroupId:       1000,
		ContainerId:    "abc123def456",
		ContainerName:  "web-server",
		Image:          "nginx:latest",
		Orchestrator:   "docker",
		PodName:        "web-pod-xyz",
		PodNamespace:   "default",
	}
	if ci.ContainerId != "abc123def456" {
		t.Errorf("id = %s", ci.ContainerId)
	}
	if ci.PodNamespace != "default" {
		t.Errorf("ns = %s", ci.PodNamespace)
	}
}

func TestContainerEventProto(t *testing.T) {
	evt := &containerpb.ContainerEvent{
		Type:            10,
		Pid:             100,
		Comm:            "bash",
		CgroupId:        5000,
		PidNamespaceId:  2000,
	}
	if evt.Type != 10 {
		t.Errorf("type = %d", evt.Type)
	}
	if evt.PidNamespaceId != 2000 {
		t.Errorf("pid_ns = %d", evt.PidNamespaceId)
	}
}

// ─── Integration test ───────────────────────────────────────

func TestV21Integration(t *testing.T) {
	// 1. Container monitor
	m := container.New()
	m.Start()
	defer m.Stop()

	// 2. Simulate cgroup resolution
	info := m.LookupOrEnqueue(99999)
	_ = info

	// 3. Build trace with container context
	req := &cli.TraceRequest{Container: "web", Depth: 5}
	events := []cli.TraceNode{
		{PID: 1, Comm: "systemd", Action: "init", Depth: 0},
		{PID: 100, Comm: "nginx", Action: "fork", ContainerName: "web-server", ContainerID: "abc123", Depth: 1},
		{PID: 101, Comm: "bash", Action: "exec", ContainerName: "web-server", ContainerID: "abc123", Depth: 2},
		{PID: 102, Comm: "curl", Action: "connect", ContainerName: "web-server", ContainerID: "abc123", Depth: 3, Target: "5.6.7.8:443"},
	}

	result := cli.BuildTraceFromEvents(events, *req)
	t.Logf("=== v2.1 Integration ===")
	t.Logf("Events filtered by container: %d", result.Total)
	t.Logf("Trace:\n%s", result.FormatText())

	if result.Total != 3 {
		t.Errorf("expected 3 web-server events, got %d", result.Total)
	}

	// Verify the full chain is intact
	for _, node := range result.Chain {
		if node.ContainerName != "web-server" {
			t.Errorf("node %d container = %s", node.PID, node.ContainerName)
		}
	}

	t.Log("v2.1 Integration OK")
}
