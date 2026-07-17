package controlplaneha

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoordinatorElectsLeaderAndPromotesFollower(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "ha-state.json")
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)

	nodeAClock := now
	nodeA := New(Config{
		Mode:            "active-passive",
		NodeID:          "cp-a",
		ConfiguredRole:  "leader",
		Peers:           []string{"cp-a:18080", "cp-b:18080"},
		StateBackend:    statePath,
		ElectionTimeout: 30 * time.Second,
		Now:             func() time.Time { return nodeAClock },
	})
	if err := nodeA.Tick(); err != nil {
		t.Fatal(err)
	}

	nodeBClock := now.Add(1 * time.Second)
	nodeB := New(Config{
		Mode:            "active-passive",
		NodeID:          "cp-b",
		ConfiguredRole:  "follower",
		Peers:           []string{"cp-a:18080", "cp-b:18080"},
		StateBackend:    statePath,
		ElectionTimeout: 30 * time.Second,
		Now:             func() time.Time { return nodeBClock },
	})
	if err := nodeB.Tick(); err != nil {
		t.Fatal(err)
	}
	status := nodeB.Status()
	if status.Role != "follower" || status.LeaderID != "cp-a" || !status.FailoverReady {
		t.Fatalf("unexpected follower status before failover: %#v", status)
	}

	nodeBClock = now.Add(45 * time.Second)
	if err := nodeB.Tick(); err != nil {
		t.Fatal(err)
	}
	status = nodeB.Status()
	if status.Role != "leader" || status.LeaderID != "cp-b" {
		t.Fatalf("expected cp-b promotion after cp-a timeout: %#v", status)
	}
	if status.FailoverReady {
		t.Fatalf("single active node should not be failover-ready: %#v", status)
	}
}

func TestCoordinatorHonorsConfiguredLeaderWhileHealthy(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "ha-state.json")
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)

	nodeA := New(Config{
		Mode:             "active-passive",
		NodeID:           "cp-a",
		ConfiguredLeader: "cp-b",
		Peers:            []string{"cp-a:18080", "cp-b:18080"},
		StateBackend:     statePath,
		Now:              func() time.Time { return now },
	})
	nodeB := New(Config{
		Mode:             "active-passive",
		NodeID:           "cp-b",
		ConfiguredLeader: "cp-b",
		Peers:            []string{"cp-a:18080", "cp-b:18080"},
		StateBackend:     statePath,
		Now:              func() time.Time { return now.Add(time.Second) },
	})
	if err := nodeA.Tick(); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Tick(); err != nil {
		t.Fatal(err)
	}
	if status := nodeA.Status(); status.LeaderID != "cp-a" {
		t.Fatalf("nodeA should report its last checkpoint until next tick: %#v", status)
	}
	if err := nodeA.Tick(); err != nil {
		t.Fatal(err)
	}
	if status := nodeA.Status(); status.LeaderID != "cp-b" || status.Role != "follower" {
		t.Fatalf("configured healthy leader was not honored: %#v", status)
	}
}

func TestCoordinatorDegradesWithoutSharedState(t *testing.T) {
	c := New(Config{
		Mode:         "active-passive",
		NodeID:       "cp-a",
		Peers:        []string{"cp-b:18080"},
		StateBackend: "local",
	})
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	status := c.Status()
	if status.FailoverReady || status.Role != "leader" {
		t.Fatalf("unexpected degraded status: %#v", status)
	}
	if status.Message == "" {
		t.Fatalf("expected degraded message: %#v", status)
	}
}

func TestCoordinatorRecognizesPostgresBackends(t *testing.T) {
	if !isPostgresBackend("postgres://providapt:secret@db:5432/providapt?sslmode=require") {
		t.Fatal("postgres:// backend should be recognized")
	}
	if !isPostgresBackend("postgresql://providapt:secret@db:5432/providapt?sslmode=require") {
		t.Fatal("postgresql:// backend should be recognized")
	}
	if isPostgresBackend("s3://bucket/key") {
		t.Fatal("non-postgres backend should not be recognized")
	}
}

func TestCoordinatorDegradesWhenPostgresUnavailable(t *testing.T) {
	c := New(Config{
		Mode:         "active-passive",
		NodeID:       "cp-a",
		Peers:        []string{"cp-b=127.0.0.2:18080"},
		StateBackend: "postgresql://providapt:bad@127.0.0.1:1/providapt?sslmode=disable",
	})
	if err := c.Tick(); err == nil {
		t.Fatal("expected postgres connection error")
	}
	status := c.Status()
	if status.FailoverReady {
		t.Fatalf("unavailable postgres must not be failover-ready: %#v", status)
	}
	if !strings.Contains(status.Message, "degraded") {
		t.Fatalf("expected degraded status: %#v", status)
	}
}

func TestCoordinatorPostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PROVIDAPT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set PROVIDAPT_TEST_POSTGRES_DSN to run PostgreSQL HA integration test")
	}
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	nodeAClock := now
	nodeA := New(Config{
		Mode:            "active-passive",
		NodeID:          "cp-a",
		Peers:           []string{"cp-a=127.0.0.1:18080", "cp-b=127.0.0.1:18081"},
		StateBackend:    dsn,
		ElectionTimeout: 30 * time.Second,
		Now:             func() time.Time { return nodeAClock },
	})
	nodeBClock := now.Add(time.Second)
	nodeB := New(Config{
		Mode:            "active-passive",
		NodeID:          "cp-b",
		Peers:           []string{"cp-a=127.0.0.1:18080", "cp-b=127.0.0.1:18081"},
		StateBackend:    dsn,
		ElectionTimeout: 30 * time.Second,
		Now:             func() time.Time { return nodeBClock },
	})
	if err := nodeA.Tick(); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Tick(); err != nil {
		t.Fatal(err)
	}
	if status := nodeB.Status(); status.LeaderID != "cp-a" || !status.FailoverReady {
		t.Fatalf("unexpected PostgreSQL HA status: %#v", status)
	}
	nodeBClock = now.Add(45 * time.Second)
	if err := nodeB.Tick(); err != nil {
		t.Fatal(err)
	}
	if status := nodeB.Status(); status.LeaderID != "cp-b" || status.Role != "leader" {
		t.Fatalf("expected PostgreSQL-backed failover: %#v", status)
	}
}
