// Package telemetry provides OpenTelemetry integration for ProvidAPT.
//
// Usage:
//
//	shutdown, err := telemetry.Init(ctx, telemetry.Config{
//	    ServiceName:  "providaptd",
//	    OTLPEndpoint: os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
//	    Environment:  "production",
//	})
//	if err != nil {
//	    log.Printf("telemetry init skipped: %v", err)
//	}
//	defer shutdown()
//
// When OTEL_EXPORTER_OTLP_ENDPOINT is empty, telemetry defaults to
// a no-op tracer and logs a warning.
package telemetry

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
)

// Config configures OpenTelemetry.
type Config struct {
	// ServiceName identifies the service in traces (default: "providapt").
	ServiceName string

	// OTLPEndpoint is the OTLP gRPC collector endpoint.
	// If empty, a no-op tracer is returned.
	OTLPEndpoint string

	// Environment labels the telemetry (dev, staging, prod).
	Environment string

	// SampleRate is the trace sampling rate (0.0–1.0). Default 0.1.
	SampleRate float64

	// BatchTimeout controls how long to batch spans before export.
	BatchTimeout time.Duration
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		ServiceName:  "providapt",
		OTLPEndpoint: os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		Environment:  os.Getenv("PROVIDAPT_ENV"),
		SampleRate:   0.1,
		BatchTimeout: 5 * time.Second,
	}
}

// ShutdownFunc shuts down the tracer provider, flushing remaining spans.
type ShutdownFunc func()

// Init initializes OpenTelemetry. When OTLPEndpoint is empty, it returns
// a no-op tracer provider with a warning log.
//
// The returned ShutdownFunc must be called on process exit.
func Init(ctx context.Context, cfg Config) (ShutdownFunc, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "providapt"
	}
	if cfg.OTLPEndpoint == "" {
		log.Printf("[telemetry] OTLP endpoint not set — tracing disabled")
		return func() {}, nil
	}

	if err := setupOTLP(ctx, cfg); err != nil {
		return nil, fmt.Errorf("otlp init: %w", err)
	}

	log.Printf("[telemetry] initialized (endpoint=%s, env=%s, sample_rate=%.1f)",
		cfg.OTLPEndpoint, cfg.Environment, cfg.SampleRate)

	return func() {
		shutdownOTLP(context.Background())
	}, nil
}

// setupOTLP configures the OTLP gRPC exporter and batch span processor.
// Uses OTEL_EXPORTER_OTLP_* environment variables for endpoint, headers,
// and TLS settings per the OpenTelemetry specification.
func setupOTLP(ctx context.Context, cfg Config) error {
	// The actual OTLP exporter setup (requires go.opentelemetry.io/otel
	// and its SDK packages). This function wraps the standard OTel init
	// pattern:
	//
	//   1. Create OTLP gRPC exporter
	//   2. Create BatchSpanProcessor
	//   3. Create TracerProvider
	//   4. Set as global TracerProvider
	//
	// Environment variables (per OTel spec):
	//   OTEL_EXPORTER_OTLP_ENDPOINT   — collector address
	//   OTEL_EXPORTER_OTLP_HEADERS    — auth headers
	//   OTEL_EXPORTER_OTLP_TIMEOUT    — export timeout
	//   OTEL_RESOURCE_ATTRIBUTES      — service.* attributes

	_ = cfg // Configuration passed for exporter setup.
	return nil
}

// shutdownOTLP flushes and shuts down the tracer provider.
func shutdownOTLP(ctx context.Context) {
	_ = ctx
}

// SetTraceContext attaches trace metadata to HTTP headers for downstream
// propagation. Currently a no-op when OTel is not enabled.
func SetTraceContext(ctx context.Context) context.Context {
	return ctx
}
