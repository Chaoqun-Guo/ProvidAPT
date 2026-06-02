//go:build linux

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/analyzer"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/loader"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/pipeline"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	storage "github.com/Chaoqun-Guo/ProvidAPT/internal/storage/format"
)

const pidFile = "/var/run/providaptd.pid"

const ringBufSize = 1024

func main() {
	cfg, err := config.Load("providapt.toml")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// ── PID file ──────────────────────────────────────────
	writePIDFile()
	defer os.Remove(pidFile)

	// ── eBPF loader ─────────────────────────────────────
	bpfLoader, err := loader.New(cfg)
	if err != nil {
		log.Fatalf("loader: %v", err)
	}
	defer bpfLoader.Close()

	// ── Ring buffer reader ──────────────────────────────
	eventCh, errCh := collector.Start(bpfLoader.RB)

	// ── Provenance graph (in-memory DAG) ────────────────
	graph := provenance.NewGraph()

	// ── Ingestion pipeline (cache + RocksDB + merge) ────
	pipeCfg := pipeline.DefaultConfig()
	pipeCfg.StorePath = filepath.Join(cfg.Output.Dir, "store")
	pipeCfg.MaxCacheSize = 8192
	pipeCfg.MergeWindow = 5 * time.Second

	pipe, err := pipeline.New(graph, pipeCfg)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}
	defer pipe.Stop()
	pipe.Start()

	// ── APT analyzer ────────────────────────────────────
	aptCfg := analyzer.DefaultConfig()
	aptCfg.ScanInterval = 30 * time.Second
	apt := analyzer.New(graph, aptCfg)
	apt.Start()
	defer apt.Stop()

	// ── Raw event log writer ────────────────────────────
	writer, err := storage.NewWriter(cfg.Output.Dir, cfg.Output.Format)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	defer writer.Close()

	// ── Shutdown signal ─────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("ProvidAPT started.")
	fmt.Println("  Events flow: RingBuf → Pipeline → Graph → Analyzer")
	fmt.Println("  Storage:     Hot nodes (LRU cache) + Cold nodes & edges (RocksDB)")
	fmt.Println("  Merge:       5s sliding window dedup")
	fmt.Println("  Backpressure: auto at 70% memory")

	eventCount := 0

loop:
	for {
		select {
		case evt := <-eventCh:
			// Pipeline: cache + merge + backpressure
			pipe.AddEvent(evt)

			// Raw log (optional, kept for compatibility)
			if err := writer.Write(evt); err != nil {
				log.Printf("write error: %v", err)
			}
			eventCount++

		case err := <-errCh:
			log.Printf("collector error: %v", err)

		case al := <-apt.AlertCh:
			log.Printf("\n*** ALERT ***\n%s", al)

		case <-pipe.PauseCh():
			// High memory pressure — pause ring buffer consumption
			log.Printf("[main] backpressure: pausing ring buffer read")
			select {
			case <-pipe.ResumeCh():
				log.Printf("[main] backpressure: resuming ring buffer read")
			case <-sigCh:
				break loop
			case <-time.After(10 * time.Second):
				log.Printf("[main] backpressure: forced resume after timeout")
			}

		case sig := <-sigCh:
			fmt.Printf("\nsignal %v, shutting down...\n", sig)
			break loop
		}
	}

	// ── Final report ────────────────────────────────────
	graphStats := graph.Stats()
	alerts := apt.Alerts()
	pipeStats := pipe.Stats()

	log.Printf("Processed %d events. Graph: %d nodes, %d edges. Alerts: %d",
		eventCount, graphStats.Nodes, graphStats.Edges, len(alerts))
	log.Printf("Pipeline: cache=%v, merge_pending=%d, disk_bytes=%v",
		pipeStats["cache"].(map[string]interface{})["size"],
		pipeStats["merger"].(map[string]interface{})["pending"],
		pipeStats["store"].(map[string]interface{})["disk_bytes"])

	// ── Serialize provenance graph ──────────────────────
	outDir := cfg.Output.Dir
	if outDir == "" {
		outDir = "."
	}
	os.MkdirAll(outDir, 0755)

	jsonPath := filepath.Join(outDir, "provenance.json")
	f, err := os.Create(jsonPath)
	if err == nil {
		defer f.Close()
		if err := graph.SerializeJSON(f); err != nil {
			log.Printf("JSON serialize error: %v", err)
		} else {
			log.Printf("Saved: %s", jsonPath)
		}
	}

	graphmlPath := filepath.Join(outDir, "provenance.graphml")
	f2, err := os.Create(graphmlPath)
	if err == nil {
		defer f2.Close()
		if err := graph.SerializeGraphML(f2); err != nil {
			log.Printf("GraphML error: %v", err)
		} else {
			log.Printf("Saved: %s", graphmlPath)
		}
	}

	// ── Serialize alerts ────────────────────────────────
	if len(alerts) > 0 {
		alertPath := filepath.Join(outDir, "alerts.json")
		f3, err := os.Create(alertPath)
		if err == nil {
			defer f3.Close()
			analyzer.SerializeAlertJSON(f3, alerts)
			log.Printf("Saved %d alerts: %s", len(alerts), alertPath)
		}
	}
}

// writePIDFile writes the daemon PID to /var/run/providaptd.pid.
func writePIDFile() {
	if err := os.MkdirAll(filepath.Dir(pidFile), 0755); err != nil {
		log.Printf("pidfile dir: %v", err)
		return
	}
	if err := ioutil.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
		log.Printf("pidfile write: %v", err)
	}
}
