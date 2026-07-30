// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package metrics provides Prometheus metrics for ProvidAPT monitoring.
package metrics

import (
	"log"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Namespace for all ProvidAPT metrics.
const namespace = "providapt"

// Metric descriptors.

var (
	registerOnce sync.Once

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

	// System health metrics.

	// CPU usage ratio (0.0–1.0), updated periodically.
	CPUUsageRatio = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "cpu_usage_ratio",
		Help:      "Process CPU usage ratio (0.0–1.0).",
	})

	// Resident set size in bytes.
	MemoryUsageBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_usage_bytes",
		Help:      "Process resident set size in bytes.",
	})

	// Total events dropped (ring buffer overflow or backpressure).
	EventsDroppedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "events_dropped_total",
		Help:      "Total events dropped (ring buffer overflow or backpressure).",
	})

	// Uptime in seconds.
	UptimeSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "uptime_seconds",
		Help:      "Process uptime in seconds.",
	})

	// Pipeline queue depth (events waiting to be processed).
	PipelineQueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "queue_depth",
		Help:      "Current number of events queued in the pipeline.",
	})
)

// MustRegister registers all metrics with the default Prometheus registry.
// Panics on registration failure.
func MustRegister() {
	registerOnce.Do(func() {
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
			CPUUsageRatio,
			MemoryUsageBytes,
			EventsDroppedTotal,
			UptimeSeconds,
			PipelineQueueDepth,
		)
		log.Printf("[metrics] registered %d Prometheus metrics", 15)
	})
}

// Handler returns the Prometheus HTTP handler for /metrics.
func Handler() http.Handler {
	return promhttp.Handler()
}
