package mgmt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPersistedControlPlaneStateFileBackend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := persistedControlPlaneState{
		SchemaVersion: 1,
		SavedAt:       time.Now().UTC(),
		Agents: map[string]persistedAgentMetadata{
			"agent-1": {Group: "prod", Tags: []string{"linux"}},
		},
		Fleet: map[string]AgentTelemetrySnapshot{
			"agent-1": {AgentID: "agent-1", Hostname: "vm-1", Status: "HEALTHY"},
		},
	}
	if err := savePersistedControlPlaneState(path, state); err != nil {
		t.Fatalf("save file state: %v", err)
	}
	loaded, ok, err := loadPersistedControlPlaneState(path)
	if err != nil {
		t.Fatalf("load file state: %v", err)
	}
	if !ok {
		t.Fatal("expected state to exist")
	}
	if loaded.Agents["agent-1"].Group != "prod" {
		t.Fatalf("agent group = %q", loaded.Agents["agent-1"].Group)
	}
	if loaded.Fleet["agent-1"].Hostname != "vm-1" {
		t.Fatalf("fleet hostname = %q", loaded.Fleet["agent-1"].Hostname)
	}
}

func TestPersistedControlPlaneStatePostgresBackendUnavailable(t *testing.T) {
	_, _, err := loadPersistedControlPlaneState("postgresql://providapt:bad@127.0.0.1:1/providapt?sslmode=disable")
	if err == nil {
		t.Fatal("expected postgres backend connection error")
	}
}

func TestPersistedControlPlaneStatePostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PROVIDAPT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set PROVIDAPT_TEST_POSTGRES_DSN to run postgres mgmt state integration")
	}
	state := persistedControlPlaneState{
		SchemaVersion: 1,
		SavedAt:       time.Now().UTC(),
		Agents: map[string]persistedAgentMetadata{
			"agent-postgres": {Group: "prod", Tags: []string{"vm"}},
		},
		Fleet: map[string]AgentTelemetrySnapshot{
			"agent-postgres": {AgentID: "agent-postgres", Hostname: "vm-postgres", Status: "HEALTHY"},
		},
	}
	if err := savePersistedControlPlaneState(dsn, state); err != nil {
		t.Fatalf("save postgres state: %v", err)
	}
	loaded, ok, err := loadPersistedControlPlaneState(dsn)
	if err != nil {
		t.Fatalf("load postgres state: %v", err)
	}
	if !ok || loaded.Agents["agent-postgres"].Group != "prod" || loaded.Fleet["agent-postgres"].Hostname != "vm-postgres" {
		t.Fatalf("loaded postgres state = %#v ok=%t", loaded, ok)
	}
}
