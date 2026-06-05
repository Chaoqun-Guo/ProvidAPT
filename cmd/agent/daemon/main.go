//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/analyzer"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/loader"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/pipeline"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	mgmt "github.com/Chaoqun-Guo/ProvidAPT/internal/policy/mgmt"
	storage "github.com/Chaoqun-Guo/ProvidAPT/internal/storage/format"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/api"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/logx"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/metrics"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/sanity"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/secure"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/supportbundle"
)

const pidFile = "/var/run/providaptd.pid"
const ringBufSize = 1024

func main() {
	// ── Panic recovery & crash snapshot ──────────────────
	defer supportbundle.HandleCrash()

	// ── CLI flags ────────────────────────────────────────────
	configPath := flag.String("config", "providapt.toml", "Path to configuration file")
	logLevel := flag.String("log-level", "", "Override log level (debug|info|warn|error)")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	// ── Load config ─────────────────────────────────────────
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		os.Exit(1)
	}

	// ── Structured logging ───────────────────────────────────
	logLevelVal := cfg.Log.Level
	if *logLevel != "" {
		logLevelVal = *logLevel // CLI flag overrides config
	}
	logx.Init(logLevelVal, cfg.Log.Format)
	logx.System().Info("starting", "version", version.String(), "config", *configPath)

	// ── Audit log store ──────────────────────────────────
	auditStore, err := audit.New(cfg.Output.Dir)
	if err != nil {
		logx.System().Warn("audit store init", "error", err)
	}
	if auditStore != nil {
		defer auditStore.Close()
		auditStore.Log(audit.Entry{
			Category: audit.CatSystem,
			Severity: "INFO",
			Message:  "Daemon starting",
			Source:   "daemon",
			Details: map[string]interface{}{
				"version": version.String(),
				"config":  *configPath,
			},
		})
		defer func() {
			auditStore.Log(audit.Entry{
				Category: audit.CatSystem,
				Severity: "INFO",
				Message:  "Daemon shutting down",
				Source:   "daemon",
			})
		}()
	}

	// ── PID file ──────────────────────────────────────────
	writePIDFile()
	defer os.Remove(pidFile)

	// ── Self-check ───────────────────────────────────────
	sanityReport := sanity.RunChecks(cfg, nil)
	for _, r := range sanityReport.Results {
		msg := r.Message
		if r.FixSuggestion != "" {
			msg += " | fix: " + r.FixSuggestion
		}
		if r.Status == sanity.FAIL {
			logx.System().Error("sanity check failed", "check", r.Name, "detail", msg)
		} else if r.Status == sanity.WARN {
			logx.System().Warn("sanity check warning", "check", r.Name, "detail", msg)
		} else {
			logx.System().Info("sanity check passed", "check", r.Name)
		}
	}
	if sanityReport.HasFailures() {
		logx.System().Error("environment check failed — aborting startup",
			"summary", sanityReport.Summary())
		os.Exit(1)
	}
	logx.System().Info("all sanity checks passed", "summary", sanityReport.Summary())

	// ── eBPF loader ─────────────────────────────────────
	bpfLoader, err := loader.New(cfg)
	if err != nil {
		logx.System().Error("loader init failed", "error", err)
		os.Exit(1)
	}
	defer bpfLoader.Close()

	// ── Encryption at rest ──────────────────────────────
	var encryptKey []byte
	if cfg.Storage.Encrypt {
		ek, err := secure.LoadOrGenerateKey(cfg.Storage.KeyFile)
		if err != nil {
			logx.System().Error("encryption key init failed", "error", err)
			os.Exit(1)
		}
		encryptKey = ek.Bytes()
		logx.System().Info("storage encryption enabled", "key_file", cfg.Storage.KeyFile)
	}

	// ── Least privilege: pin eBPF maps & drop root ──────
	if secure.IsPrivileged() {
		bpfLoader.PinMaps("/sys/fs/bpf/providapt")

		// Apply default excludes before dropping privileges
		if err := bpfLoader.Ctrl.DefaultExcludes(); err != nil {
			logx.System().Warn("default excludes failed", "error", err)
		}

		if err := secure.EnsureDataDirOwnership(cfg.Output.Dir); err != nil {
			logx.System().Warn("data dir ownership", "error", err)
		}
		if err := secure.DropPrivileges(); err != nil {
			logx.System().Error("privilege drop failed", "error", err)
			os.Exit(1)
		}
		logx.System().Info("privileges dropped to providapt user")
	}

	// ── Ring buffer reader ──────────────────────────────
	eventCh, errCh := collector.Start(bpfLoader.RB)

	// ── Provenance graph (in-memory DAG) ────────────────
	graph := provenance.NewGraph()

	// ── Ingestion pipeline (cache + RocksDB + merge) ────
	pipeCfg := pipeline.DefaultConfig()
	pipeCfg.StorePath = filepath.Join(cfg.Output.Dir, "store")
	pipeCfg.MaxCacheSize = 8192
	pipeCfg.MergeWindow = 5 * time.Second
	pipeCfg.EncryptionKey = encryptKey

	pipe, err := pipeline.New(graph, pipeCfg)
	if err != nil {
		logx.System().Error("pipeline init failed", "error", err)
		os.Exit(1)
	}
	defer pipe.Stop()
	pipe.Start()

	// ── APT analyzer ────────────────────────────────────
	aptCfg := analyzer.DefaultConfig()
	aptCfg.ScanInterval = 30 * time.Second
	apt := analyzer.New(graph, aptCfg)
	apt.Start()
	defer apt.Stop()

	// ── Connect sketch integrator (graph anomaly detection) ──
	si := analyzer.NewSketchIntegrator(analyzer.DefaultSketchConfig())
	apt.SetSketchIntegrator(si)
	defer si.Stop()

	// ── Raw event log writer ────────────────────────────
	writer, err := storage.NewWriter(cfg.Output.Dir, cfg.Output.Format)
	if err != nil {
		logx.System().Error("storage writer init failed", "error", err)
		os.Exit(1)
	}
	defer writer.Close()

	// ── API server with /health and /metrics ────────────
	apiServer := api.NewServer(cfg.API.REST, graph, nil)
	metrics.MustRegister()

	// Health check closure — populated every iteration
	var (
		eventsIngested  uint64
		eventsDropped   uint64
		pipelineHealthy = true
		storeHealthy    = true
		sanityPassed    = !sanityReport.HasFailures()
		startTime       = time.Now()
	)

	apiServer.SetHealthFunc(func() api.HealthStatus {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		hs := api.HealthStatus{
			Status:          healthStatus(pipelineHealthy, storeHealthy),
			UptimeSeconds:   int64(time.Since(startTime).Seconds()),
			EbpfCollector:   bpfLoader.RB != nil,
			PipelineHealthy: pipelineHealthy,
			StoreHealthy:    storeHealthy,
			EventsIngested:  eventsIngested,
			EventsDropped:   eventsDropped,
			MemoryBytes:     m.Alloc,
			Version:         version.String(),
		}
		if sanityPassed {
			hs.SanityCheck = "pass"
		} else {
			hs.SanityCheck = "fail"
		}
		return hs
	})

	go func() {
		logx.System().Info("api server starting", "addr", cfg.API.REST)
		if err := apiServer.Start(); err != nil {
			logx.System().Error("api server error", "error", err)
		}
	}()

	// ── gRPC management server (mTLS) ──────────────────
	if cfg.TLS.Enable {
		mgmtCfg := &mgmt.ServerConfig{
			ListenAddr:        cfg.API.GRPC,
			CertFile:          cfg.TLS.CertFile,
			KeyFile:           cfg.TLS.KeyFile,
			CAFile:            cfg.TLS.CAFile,
			EnableTLS:         true,
			RequireClientCert: true,
		}
		mgmtServer, err := mgmt.NewServer(mgmtCfg)
		if err != nil {
			logx.System().Error("mgmt server init failed", "error", err)
			os.Exit(1)
		}
		mgmtServer.SetController(bpfLoader.Ctrl)
		mgmtServer.SetAnalyzer(apt)
		mgmtServer.StartAlertForwarder(apt.AlertCh)
		if err := mgmtServer.Start(); err != nil {
			logx.System().Error("mgmt server start failed", "error", err)
			os.Exit(1)
		}
		defer mgmtServer.Stop()
		logx.System().Info("mgmt gRPC server started", "addr", cfg.API.GRPC, "tls", true)
	}

	// ── Real-time alert persistence (NDJSON) ──────────────
	alertPath := filepath.Join(cfg.Output.Dir, "alerts.ndjson")
	alertFile, err := os.OpenFile(alertPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logx.System().Error("alert file open failed", "error", err)
	}
	var alertEnc *json.Encoder
	if alertFile != nil {
		alertEnc = json.NewEncoder(alertFile)
		defer alertFile.Close()
	}

	// ── Signals: shutdown (SIGINT/SIGTERM) + reload (SIGHUP) ──
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	logx.System().Info("daemon started",
		"events", "RingBuf → Pipeline → Graph → Analyzer",
		"storage", "Hot nodes (LRU cache) + Cold nodes & edges (RocksDB)",
		"merge", "5s sliding window dedup",
		"backpressure", "auto at 70% memory",
	)

	eventCount := 0
	metricsTicker := time.NewTicker(15 * time.Second)
	defer metricsTicker.Stop()

loop:
	for {
		select {
		case evt := <-eventCh:
			pipe.AddEvent(evt)
			if err := writer.Write(evt); err != nil {
				logx.System().Error("event write error", "error", err)
				storeHealthy = false
			} else {
				storeHealthy = true
			}
			eventCount++
			eventsIngested = uint64(eventCount)

			// Track dropped events via backpressure signal
			select {
			case <-pipe.PauseCh():
				eventsDropped++
			default:
			}

			// Update metrics
			metrics.EventsIngested.Inc()
			metrics.PipelineEventsProcessed.Inc()

		case err := <-errCh:
			logx.System().Error("collector error", "error", err)

		case al := <-apt.AlertCh:
			logx.System().Warn("alert triggered", "alert", fmt.Sprintf("%s", al))
			logx.Audit().Warn("security_alert", "alert", fmt.Sprintf("%s", al))
			if alertEnc != nil {
				if err := alertEnc.Encode(al); err != nil {
					logx.System().Error("alert write failed", "error", err)
				}
			}

		case <-pipe.PauseCh():
			logx.System().Warn("backpressure: pausing ring buffer read")
			pipelineHealthy = false
			metrics.PipelineBackpressure.Inc()
			select {
			case <-pipe.ResumeCh():
				logx.System().Info("backpressure: resuming ring buffer read")
				pipelineHealthy = true
			case <-sigCh:
				break loop
			case <-time.After(10 * time.Second):
				logx.System().Warn("backpressure: forced resume after timeout")
				pipelineHealthy = true
			}

		case <-metricsTicker.C:
			// Periodic system metric updates
			updateSystemMetrics(startTime, eventsDropped)

			// systemd watchdog heartbeat
			sdNotifyWatchdog()

		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				logx.System().Info("SIGHUP received, reloading config")
				newCfg, err := config.Load(*configPath)
				if err != nil {
					logx.System().Error("config reload failed", "error", err)
					continue
				}
				// Reload analyzer config (atomic pointer swap)
				newAptCfg := &analyzer.Config{
					ScanInterval:       time.Duration(newCfg.Analyzer.ScanInterval.Duration),
					DeepTaintThreshold: newCfg.Analyzer.DeepTaintThreshold,
					Quiet:              newCfg.Analyzer.Quiet,
				}
				for _, p := range newCfg.Analyzer.EnablePatterns {
					newAptCfg.EnablePatterns = append(newAptCfg.EnablePatterns, analyzer.PatternID(p))
				}
				apt.ReloadConfig(newAptCfg)

				// Reload taint seeds
				if newCfg.TaintSecrets.UntrustedComms != nil || newCfg.TaintSecrets.NetworkTools != nil {
					untrusted := make(map[string]bool)
					for _, c := range newCfg.TaintSecrets.UntrustedComms {
						untrusted[c] = true
					}
					network := make(map[string]bool)
					for _, c := range newCfg.TaintSecrets.NetworkTools {
						network[c] = true
					}
					analyzer.ReloadTaintSeeds(untrusted, network, newCfg.TaintSecrets.SensitivePaths)
				}

				// Update log level if changed
				if newCfg.Log.Level != cfg.Log.Level {
					logx.Init(newCfg.Log.Level, newCfg.Log.Format)
				}

				cfg = newCfg
				logx.System().Info("config reloaded successfully")
				continue
			}
			logx.System().Info("shutdown signal received", "signal", fmt.Sprintf("%v", sig))
			fmt.Printf("\nsignal %v, shutting down...\n", sig)
			break loop
		}
	}

	// ── Final report ────────────────────────────────────
	graphStats := graph.Stats()
	alerts := apt.Alerts()
	pipeStats := pipe.Stats()

	logx.System().Info("shutdown complete",
		"events_processed", eventCount,
		"graph_nodes", graphStats.Nodes,
		"graph_edges", graphStats.Edges,
		"alerts", len(alerts),
	)

	if cache, ok := pipeStats["cache"].(map[string]interface{}); ok {
		logx.System().Info("pipeline stats", "cache_size", cache["size"])
	}

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
			logx.System().Error("JSON serialize error", "error", err)
		} else {
			logx.System().Info("saved graph JSON", "path", jsonPath)
		}
	}

	graphmlPath := filepath.Join(outDir, "provenance.graphml")
	f2, err := os.Create(graphmlPath)
	if err == nil {
		defer f2.Close()
		if err := graph.SerializeGraphML(f2); err != nil {
			logx.System().Error("GraphML error", "error", err)
		} else {
			logx.System().Info("saved graph GraphML", "path", graphmlPath)
		}
	}

}

// writePIDFile writes the daemon PID to /var/run/providaptd.pid.
func writePIDFile() {
	if err := os.MkdirAll(filepath.Dir(pidFile), 0755); err != nil {
		logx.System().Error("pidfile dir error", "error", err)
		return
	}
	if err := ioutil.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
		logx.System().Error("pidfile write error", "error", err)
	}
}

// updateSystemMetrics pushes system-level Prometheus metrics.
func updateSystemMetrics(startTime time.Time, eventsDropped uint64) {
	metrics.UptimeSeconds.Set(time.Since(startTime).Seconds())
	metrics.EventsDroppedTotal.Add(float64(eventsDropped))

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	metrics.MemoryUsageBytes.Set(float64(m.Alloc))

	// Approximate CPU: goroutines as a proxy
	metrics.CPUUsageRatio.Set(float64(runtime.NumGoroutine()) / 1000.0)
}

// healthStatus returns "healthy" when all subsystems are OK, else "unhealthy".
func healthStatus(pipelineHealthy, storeHealthy bool) string {
	if pipelineHealthy && storeHealthy {
		return "healthy"
	}
	return "unhealthy"
}

// sdNotifyWatchdog sends a systemd watchdog heartbeat via NOTIFY_SOCKET.
func sdNotifyWatchdog() {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	// Abstract namespace sockets start with @ — replace with null byte
	if socket[0] == '@' {
		socket = "\x00" + socket[1:]
	}
	addr := &net.UnixAddr{Name: socket, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte("WATCHDOG=1"))
}
