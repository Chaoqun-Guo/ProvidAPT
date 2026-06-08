package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSender struct {
	err      error
	calls    int
	lastType string
	lastData []byte
}

func (f *fakeSender) SendWithContentType(data []byte, contentType string) error {
	f.calls++
	f.lastType = contentType
	f.lastData = append([]byte(nil), data...)
	return f.err
}

func (f *fakeSender) Close() {}

func TestReporterReportNowSuccess(t *testing.T) {
	sender := &fakeSender{}
	reporter := NewReporter(ReporterConfig{Endpoint: "127.0.0.1:50051", Interval: time.Second}, func() Summary {
		return Summary{AgentID: "agent-1", Status: "HEALTHY"}
	})
	reporter.SetSender(sender)

	if err := reporter.ReportNow(); err != nil {
		t.Fatalf("ReportNow: %v", err)
	}
	if sender.calls != 1 {
		t.Fatalf("calls = %d, want 1", sender.calls)
	}
	if sender.lastType != "summary" {
		t.Fatalf("content type = %q, want summary", sender.lastType)
	}
	if reporter.Status().ConsecutiveFailures != 0 {
		t.Fatal("expected no failures after success")
	}
	if reporter.Status().LastSuccess.IsZero() {
		t.Fatal("expected last success timestamp")
	}
}

func TestReporterReportNowFailure(t *testing.T) {
	sender := &fakeSender{err: errors.New("send failed")}
	reporter := NewReporter(ReporterConfig{Endpoint: "127.0.0.1:50051"}, func() Summary {
		return Summary{AgentID: "agent-1", Status: "ERROR"}
	})
	reporter.SetSender(sender)

	if err := reporter.ReportNow(); err == nil {
		t.Fatal("expected error")
	}
	status := reporter.Status()
	if status.ConsecutiveFailures != 1 {
		t.Fatalf("failures = %d, want 1", status.ConsecutiveFailures)
	}
	if status.LastError == "" {
		t.Fatal("expected last error")
	}
}

func TestReporterStartDisabled(t *testing.T) {
	reporter := NewReporter(ReporterConfig{}, func() Summary { return Summary{} })
	if err := reporter.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if reporter.Status().Enabled {
		t.Fatal("expected disabled status without endpoint")
	}
}
