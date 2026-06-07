package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/status":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "running", "nodes": 42, "edges": 128,
			})
		case "/health":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "healthy", "uptime_seconds": 3600,
			})
		case "/api/v1/graph/export":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"node_count": 2, "edge_count": 1,
				},
				"elements": []map[string]interface{}{
					{"group": "nodes", "data": map[string]interface{}{"id": "p:1"}},
					{"group": "nodes", "data": map[string]interface{}{"id": "f:100"}},
					{"group": "edges", "data": map[string]interface{}{
						"id": "e1", "source": "p:1", "target": "f:100",
					}},
				},
			})
		case "/api/v1/alerts":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"alerts": []map[string]interface{}{
					{"id": "alert-1", "title": "Suspicious exec", "severity": "HIGH"},
				},
				"count": 1,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		}
	}))
}

func TestClientStatus(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	c := New(srv.URL)
	status, err := c.Status()
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if status.Status != "running" {
		t.Errorf("status = %q, want running", status.Status)
	}
	if status.Nodes != 42 {
		t.Errorf("nodes = %d, want 42", status.Nodes)
	}
}

func TestClientHealth(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	c := New(srv.URL)
	health, err := c.Health()
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
	if health.Status != "healthy" {
		t.Errorf("status = %q, want healthy", health.Status)
	}
	if health.UptimeSeconds != 3600 {
		t.Errorf("uptime = %d, want 3600", health.UptimeSeconds)
	}
}

func TestClientExportGraph(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	c := New(srv.URL)
	graph, err := c.ExportGraph("")
	if err != nil {
		t.Fatalf("ExportGraph() error: %v", err)
	}
	if graph.Data.NodeCount != 2 {
		t.Errorf("nodes = %d, want 2", graph.Data.NodeCount)
	}
	if len(graph.Elements) != 3 {
		t.Errorf("elements = %d, want 3", len(graph.Elements))
	}
}

func TestClientAlerts(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	c := New(srv.URL)
	alerts, err := c.Alerts()
	if err != nil {
		t.Fatalf("Alerts() error: %v", err)
	}
	if alerts.Count != 1 {
		t.Errorf("count = %d, want 1", alerts.Count)
	}
	if len(alerts.Alerts) != 1 {
		t.Errorf("alerts = %d, want 1", len(alerts.Alerts))
	}
}

func TestClientAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "running"})
	}))
	defer srv.Close()

	c := New(srv.URL, WithAPIKey("test-key"))
	status, err := c.Status()
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if status.Status != "running" {
		t.Errorf("status = %q", status.Status)
	}
}

func TestClientNotFound(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.TraceNode("p:999", "backward", 5)
	if err == nil {
		t.Error("expected error for unknown trace")
	}
}

func TestClientOptions(t *testing.T) {
	c := New("http://localhost:8080",
		WithAPIKey("key"),
		WithTimeout(5*time.Second),
	)
	if c.apiKey != "key" {
		t.Errorf("apiKey = %q", c.apiKey)
	}
	if c.httpClient.Timeout != 5*time.Second {
		t.Errorf("timeout = %v", c.httpClient.Timeout)
	}
}
