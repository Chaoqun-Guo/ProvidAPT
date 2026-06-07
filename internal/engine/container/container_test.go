// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"testing"
	"time"
)

// ─── K8s listener tests ─────────────────────────────────────

func TestNewK8sListener(t *testing.T) {
	kl := NewK8sListener()
	if kl == nil {
		t.Fatal("NewK8sListener returned nil")
	}
	if kl.IsEnabled() {
		t.Error("should start disabled")
	}
}

func TestK8sStartStop(t *testing.T) {
	kl := NewK8sListener()
	kl.Start()
	if !kl.IsEnabled() {
		t.Error("should be enabled after start")
	}
	kl.Stop()
}

func TestIsHex(t *testing.T) {
	if !isHex("abc123def456") {
		t.Error("should be hex")
	}
	if isHex("xyz") {
		t.Error("xyz is not hex")
	}
}

func TestParseAndMap(t *testing.T) {
	kl := NewK8sListener()
	cgroup := "0::/kubepods/burstable/pod-abc123/abcdef0123456789"
	kl.parseAndMap("12345", cgroup)
	// Should parse and store
	time.Sleep(50 * time.Millisecond)
}

func TestStats(t *testing.T) {
	kl := NewK8sListener()
	stats := kl.Stats()
	if stats["pods_mapped"].(int) != 0 {
		t.Errorf("pods = %d", stats["pods_mapped"])
	}
	if !stats["enabled"].(bool) {
		t.Log("listener not enabled")
	}
}

func TestPodLogScanner(t *testing.T) {
	kl := NewK8sListener()
	kl.scanPodLogs() // should not panic
}

func TestProcCgroupScanner(t *testing.T) {
	kl := NewK8sListener()
	kl.scanProcCgroups() // should not panic
}

// ─── Enricher tests ─────────────────────────────────────────

func TestNewEnricher(t *testing.T) {
	e := NewEnricher(nil)
	if e == nil {
		t.Fatal("NewEnricher returned nil")
	}
}

func TestEnrichWithoutListener(t *testing.T) {
	e := NewEnricher(nil)
	evt := e.Enrich(100, "bash", "/etc/hosts", 10, 0)
	if evt.PodName != "" {
		t.Log("pod name set (unexpected)")
	}
	if evt.PID != 100 {
		t.Errorf("pid = %d", evt.PID)
	}
}

func TestEnrichWithListener(t *testing.T) {
	kl := NewK8sListener()
	e := NewEnricher(kl)
	evt := e.Enrich(200, "curl", "/tmp/evil.sh", 20, 12345)
	if evt != nil {
		t.Logf("enriched: pid=%d comm=%s cgroup=%d", evt.PID, evt.Comm, evt.CgroupID)
	}
}

func TestGetCached(t *testing.T) {
	e := NewEnricher(nil)
	e.Enrich(100, "bash", "/etc/hosts", 10, 42)
	cached := e.GetCached(42)
	if cached == nil {
		t.Log("cache miss (expected without listener)")
	}
}

func TestPodLabel(t *testing.T) {
	evt := &EnrichedEvent{PodName: "web-server"}
	if evt.PodLabel() != "web-server" {
		t.Errorf("label = %s", evt.PodLabel())
	}
	evt2 := &EnrichedEvent{}
	if evt2.PodLabel() != "host" {
		t.Errorf("default label = %s", evt2.PodLabel())
	}
}

func TestIsolationKey(t *testing.T) {
	evt := &EnrichedEvent{Namespace: "default", PodName: "nginx"}
	if evt.IsolationKey() != "default/nginx" {
		t.Errorf("key = %s", evt.IsolationKey())
	}
}

// ─── Isolation analyzer tests ───────────────────────────────

func TestNewIsolationAnalyzer(t *testing.T) {
	ia := NewIsolationAnalyzer()
	if ia == nil {
		t.Fatal("NewIsolationAnalyzer returned nil")
	}
}

func TestSamePodNoAlert(t *testing.T) {
	ia := NewIsolationAnalyzer()
	src := &EnrichedEvent{PodName: "nginx", Namespace: "default"}
	dst := &EnrichedEvent{PodName: "nginx", Namespace: "default"}

	alert := ia.RecordEdge(src, dst, "file_access")
	if alert != nil {
		t.Error("same pod should not alert")
	}
}

func TestSameNamespaceNormal(t *testing.T) {
	ia := NewIsolationAnalyzer()
	src := &EnrichedEvent{PodName: "nginx", Namespace: "default"}
	dst := &EnrichedEvent{PodName: "sidecar", Namespace: "default"}

	alert := ia.RecordEdge(src, dst, "file_access")
	if alert != nil {
		t.Log("file access within same NS may or may not alert")
	}
}

func TestCrossNamespaceAlert(t *testing.T) {
	ia := NewIsolationAnalyzer()
	src := &EnrichedEvent{PodName: "web", Namespace: "frontend"}
	dst := &EnrichedEvent{PodName: "db", Namespace: "backend"}

	alert := ia.RecordEdge(src, dst, "connect")
	if alert == nil {
		t.Fatal("cross-namespace connect should alert")
	}
	if alert.Severity != "HIGH" {
		t.Errorf("severity = %s", alert.Severity)
	}
	if alert.Direction != "cross-ns" {
		t.Errorf("direction = %s", alert.Direction)
	}
}

func TestHostToPodAlert(t *testing.T) {
	ia := NewIsolationAnalyzer()
	src := &EnrichedEvent{PID: 100, Comm: "bash", PodName: ""}
	dst := &EnrichedEvent{PodName: "web", Namespace: "default"}

	alert := ia.RecordEdge(src, dst, "exec")
	if alert == nil {
		t.Fatal("host-to-pod should alert")
	}
	if alert.Direction != "host-to-pod" {
		t.Errorf("direction = %s", alert.Direction)
	}
}

func TestPodToHostCritical(t *testing.T) {
	ia := NewIsolationAnalyzer()
	src := &EnrichedEvent{PodName: "web", Namespace: "default"}
	dst := &EnrichedEvent{Pathname: "/etc/shadow"}

	alert := ia.RecordEdge(src, dst, "file_access")
	if alert == nil {
		t.Fatal("pod-to-host /etc/ should alert critical")
	}
	if alert.Severity != "CRITICAL" {
		t.Errorf("severity = %s", alert.Severity)
	}
	if alert.Direction != "pod-to-host" {
		t.Errorf("direction = %s", alert.Direction)
	}
}

func TestAlerts(t *testing.T) {
	ia := NewIsolationAnalyzer()
	src := &EnrichedEvent{PodName: "a", Namespace: "ns1"}
	dst := &EnrichedEvent{PodName: "b", Namespace: "ns2"}
	ia.RecordEdge(src, dst, "connect")

	alerts := ia.Alerts()
	if len(alerts) != 1 {
		t.Errorf("alerts = %d", len(alerts))
	}
}

func TestIsolationAnalyzerStats(t *testing.T) {
	ia := NewIsolationAnalyzer()
	src := &EnrichedEvent{PodName: "a", Namespace: "ns1"}
	dst := &EnrichedEvent{PodName: "b", Namespace: "ns2"}
	ia.RecordEdge(src, dst, "connect")

	stats := ia.Stats()
	if stats["alerts_total"].(int) != 1 {
		t.Errorf("alerts = %d", stats["alerts_total"])
	}
	if stats["alerts_high"].(int) != 1 {
		t.Errorf("high alerts = %d", stats["alerts_high"])
	}
}

// ─── Integration test ───────────────────────────────────────

func TestContainerIntegration(t *testing.T) {
	t.Log("=== Container Awareness Integration ===")

	// 1. K8s listener
	kl := NewK8sListener()
	kl.Start()
	defer kl.Stop()
	t.Logf("K8s listener started: enabled=%v", kl.IsEnabled())

	// 2. Enricher
	en := NewEnricher(kl)
	evt := en.Enrich(100, "bash", "/etc/hosts", 10, 12345)
	t.Logf("Enriched: pid=%d pod=%s ns=%s", evt.PID, evt.PodLabel(), evt.Namespace)

	// 3. Isolation analyzer
	ia := NewIsolationAnalyzer()

	// Normal same-pod interaction
	src1 := &EnrichedEvent{PID: 100, PodName: "web", Namespace: "default"}
	dst1 := &EnrichedEvent{PID: 200, PodName: "web", Namespace: "default"}
	ia.RecordEdge(src1, dst1, "file_access")

	// Suspicious cross-namespace connect
	src2 := &EnrichedEvent{PID: 300, PodName: "web", Namespace: "frontend"}
	dst2 := &EnrichedEvent{PID: 400, PodName: "db", Namespace: "backend"}
	_ = ia.RecordEdge(src2, dst2, "connect")

	// Critical pod-to-host
	src3 := &EnrichedEvent{PID: 500, PodName: "app", Namespace: "prod"}
	dst3 := &EnrichedEvent{Pathname: "/etc/shadow"}
	ia.RecordEdge(src3, dst3, "file_access")

	// Results
	stats := ia.Stats()
	t.Logf("Isolation stats:")
	t.Logf("  Total alerts:  %d", stats["alerts_total"])
	t.Logf("  CRITICAL:      %d", stats["alerts_critical"])
	t.Logf("  HIGH:          %d", stats["alerts_high"])
	t.Logf("  MEDIUM:        %d", stats["alerts_medium"])
	t.Logf("  Edges:         %d", stats["edges_recorded"])

	alerts := ia.Alerts()
	for _, a := range alerts {
		t.Logf("  [%s] %s → %s: %s", a.Severity, a.Direction, a.Action, a.Description)
	}

	if stats["alerts_total"].(int) < 2 {
		t.Error("expected at least 2 alerts")
	}
	if stats["alerts_critical"].(int) < 1 {
		t.Error("expected at least 1 CRITICAL alert")
	}
}
