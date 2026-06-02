package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsRegistered(t *testing.T) {
	// Reset the default registry for test isolation
	registry := prometheus.NewRegistry()
	registry.MustRegister(
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
	// Success if no panics
}

func TestEventsIngested(t *testing.T) {
	EventsIngested.Add(10)
	// Verify via Collect
	count := testutil.ToFloat64(EventsIngested)
	if count != 10 {
		t.Errorf("EventsIngested = %f, want 10", count)
	}
	EventsIngested.Add(5)
	count = testutil.ToFloat64(EventsIngested)
	if count != 15 {
		t.Errorf("EventsIngested = %f, want 15", count)
	}
}

func TestEventsParseErrors(t *testing.T) {
	EventsParseErrors.Add(3)
	count := testutil.ToFloat64(EventsParseErrors)
	if count != 3 {
		t.Errorf("EventsParseErrors = %f, want 3", count)
	}
}

func TestGraphMetrics(t *testing.T) {
	GraphNodes.Set(100)
	GraphEdges.Set(500)

	nodes := testutil.ToFloat64(GraphNodes)
	edges := testutil.ToFloat64(GraphEdges)

	if nodes != 100 {
		t.Errorf("GraphNodes = %f, want 100", nodes)
	}
	if edges != 500 {
		t.Errorf("GraphEdges = %f, want 500", edges)
	}
}

func TestGrpcMetrics(t *testing.T) {
	GrpcSentBytes.Add(1024)
	GrpcSendErrors.Add(1)

	sent := testutil.ToFloat64(GrpcSentBytes)
	errs := testutil.ToFloat64(GrpcSendErrors)

	if sent != 1024 {
		t.Errorf("GrpcSentBytes = %f, want 1024", sent)
	}
	if errs != 1 {
		t.Errorf("GrpcSendErrors = %f, want 1", errs)
	}
}

func TestAlertsTriggered(t *testing.T) {
	AlertsTriggered.WithLabelValues("CRITICAL").Add(2)
	AlertsTriggered.WithLabelValues("HIGH").Add(5)
	AlertsTriggered.WithLabelValues("MEDIUM").Add(3)

	critical := testutil.ToFloat64(AlertsTriggered.WithLabelValues("CRITICAL"))
	if critical != 2 {
		t.Errorf("CRITICAL alerts = %f, want 2", critical)
	}
}

func TestPipelineMetrics(t *testing.T) {
	PipelineEventsProcessed.Add(1000)
	PipelineBackpressure.Add(7)

	processed := testutil.ToFloat64(PipelineEventsProcessed)
	bp := testutil.ToFloat64(PipelineBackpressure)

	if processed != 1000 {
		t.Errorf("PipelineEventsProcessed = %f, want 1000", processed)
	}
	if bp != 7 {
		t.Errorf("PipelineBackpressure = %f, want 7", bp)
	}
}

func TestMustRegister(t *testing.T) {
	// Should not panic
	MustRegister()
}

func TestHandler(t *testing.T) {
	h := Handler()
	if h == nil {
		t.Error("Handler returned nil")
	}
}

func TestMetricNames(t *testing.T) {
	// Verify metric descriptors have correct names
	if EventsIngested.Desc().String() == "" {
		t.Error("empty metric descriptor")
	}
}

func TestCounterVec(t *testing.T) {
	// Test that counter vec works with multiple label values
	AlertsTriggered.WithLabelValues("INFO").Add(1)
	AlertsTriggered.WithLabelValues("WARN").Add(1)

	info := testutil.ToFloat64(AlertsTriggered.WithLabelValues("INFO"))
	if info == 0 {
		t.Error("INFO count should not be 0")
	}
}
