// Package loadtest implements API load/stress testing for ProvidAPT.
//
// Run:
//
//	go test -run=^$ -bench=BenchmarkAPI -benchtime=10x -count=1
//	go test -run=^$ -bench=BenchmarkAPI -benchtime=100x -count=1
package loadtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/api"
)

// benchmarkGraph creates a graph with n events for benchmarking.
func benchmarkGraph(n int) *provenance.Graph {
	g := provenance.NewGraph()
	for i := 0; i < n; i++ {
		g.AddEvent(&collector.Event{
			Type: syscall.EventProcessFork,
			PID:  uint32(1000 + i),
			PPID: 1,
			Comm: "benchmark",
		})
		g.AddEvent(&collector.Event{
			Type:     syscall.EventFileOpen,
			PID:      uint32(1000 + i),
			Pathname: "/etc/config",
		})
		g.AddEvent(&collector.Event{
			Type:     syscall.EventNetConnect,
			PID:      uint32(1000 + i),
			Pathname: "192.168.1.1:443",
		})
	}
	return g
}

func BenchmarkAPIStatus(b *testing.B) {
	g := benchmarkGraph(100)
	srv := api.NewServer(":0", g, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(ts.URL + "/api/v1/status")
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}

func BenchmarkAPIExport(b *testing.B) {
	g := benchmarkGraph(500)
	srv := api.NewServer(":0", g, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(ts.URL + "/api/v1/graph/export")
		if err != nil {
			b.Fatal(err)
		}
		var dst interface{}
		json.NewDecoder(resp.Body).Decode(&dst)
		resp.Body.Close()
	}
}

func BenchmarkAPIExportLarge(b *testing.B) {
	g := benchmarkGraph(5000)
	srv := api.NewServer(":0", g, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(ts.URL + "/api/v1/graph/export")
		if err != nil {
			b.Fatal(err)
		}
		var dst interface{}
		json.NewDecoder(resp.Body).Decode(&dst)
		resp.Body.Close()
	}
}

func BenchmarkAPIHealth(b *testing.B) {
	g := benchmarkGraph(100)
	srv := api.NewServer(":0", g, nil)
	srv.SetHealthFunc(func() api.HealthStatus {
		return api.HealthStatus{
			Status:        "healthy",
			UptimeSeconds: 3600,
			Version:       "test",
		}
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(ts.URL + "/health")
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}

// BenchmarkConcurrentAPI tests concurrent request throughput.
func BenchmarkConcurrentAPI(b *testing.B) {
	g := benchmarkGraph(1000)
	srv := api.NewServer(":0", g, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	concurrency := []int{1, 4, 8, 16}
	for _, c := range concurrency {
		b.Run(fmt.Sprintf("concurrency=%d", c), func(b *testing.B) {
			sem := make(chan struct{}, c)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sem <- struct{}{}
				go func() {
					resp, err := http.Get(ts.URL + "/api/v1/status")
					if err == nil {
						resp.Body.Close()
					}
					<-sem
				}()
			}
			// drain
			for i := 0; i < cap(sem); i++ {
				sem <- struct{}{}
			}
		})
	}
}
