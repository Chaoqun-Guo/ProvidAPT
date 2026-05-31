// Package metrics provides Prometheus metrics for ProvidAPT monitoring.
package metrics

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Namespace for all ProvidAPT metrics.
const namespace = "providapt"

// ─── Metric descriptors ──────────────────────────────────────────

var (
	// Events ingested from the eBPF ring buffer.
	EventsIngested = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "events_ingested_total",
		Help:      "Total events read from the eBPF ring buffer.",
	})

	// Events that failed to parse.
	EventsParseErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "events_parse_errors_total",
		Help:      "Events that could not be decoded from raw ring buffer data.",
	})

	// Graph metrics.
	GraphNodes = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "graph_nodes",
		Help:      "Current number of nodes in the provenance graph.",
	})
	GraphEdges = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "graph_edges",
		Help:      "Current number of edges in the provenance graph.",
	})

	// gRPC transport.
	GrpcSentBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "grpc",
		Name:      "sent_bytes_total",
		Help:      "Total bytes sent via gRPC transport.",
	})
	GrpcSendErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "grpc",
		Name:      "send_errors_total",
		Help:      "Number of failed gRPC Send calls.",
	})
	GrpcSendDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "grpc",
		Name:      "send_duration_seconds",
		Help:      "Latency of gRPC Send calls.",
		Buckets:   prometheus.DefBuckets,
	})

	// Detection alerts.
	AlertsTriggered = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "alerts_triggered_total",
		Help:      "Total alerts triggered, by severity.",
	}, []string{"severity"})

	// Pipeline processing.
	PipelineEventsProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "events_processed_total",
		Help:      "Total events processed by the pipeline.",
	})
	PipelineBackpressure = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "backpressure_events_total",
		Help:      "Total backpressure events triggered.",
	})
)

// MustRegister registers all metrics with the default Prometheus registry.
// Panics on registration failure.
func MustRegister() {
	r := prometheus.DefaultRegisterer
	r.MustRegister(
		EventsIngested,
		EventsParseErrors,
		GraphNodes,
		GraphEdges,
		GrpcSentBytes,
		GrpcSendErrors,
		GrpcSendDuration,
		AlertsTriggered,
		PipelineEventsProcessed,
		PipelineBackpressure,
	)
	log.Printf("[metrics] registered %d Prometheus metrics", 10)
}

// Handler returns the Prometheus HTTP handler for /metrics.
func Handler() http.Handler {
	return promhttp.Handler()
}
