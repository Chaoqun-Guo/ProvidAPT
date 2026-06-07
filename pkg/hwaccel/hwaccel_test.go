// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package hwaccel

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// ── SmartNIC tests ──────────────────────────────────────────

func TestDetectSmartNIC(t *testing.T) {
	nic := DetectSmartNIC()
	if nic == nil {
		t.Fatal("DetectSmartNIC returned nil")
	}
	t.Logf("SmartNIC: present=%v driver=%s model=%s bpf=%v",
		nic.Present, nic.Driver, nic.Model, nic.BPFSupport)
}

func TestOffloadConfig(t *testing.T) {
	nic := DetectSmartNIC()
	cfg := OffloadConfig(nic)
	if cfg == nil {
		t.Fatal("OffloadConfig returned nil")
	}
	t.Logf("Offload: socket=%v network=%v iface=%s",
		cfg.OffloadSocketEvents, cfg.OffloadNetworkEvents, cfg.NicInterface)
}

func TestApplyOffload(t *testing.T) {
	err := ApplyOffload(nil)
	if err != nil {
		t.Logf("ApplyOffload nil: %v", err)
	}
	err = ApplyOffload(&SmartNICConfig{NicInterface: "eth0"})
	if err != nil {
		t.Logf("ApplyOffload (may fail without root/NIC): %v", err)
	}
}

func TestIsAvailable(t *testing.T) {
	if IsAvailable(nil) {
		t.Error("nil should not be available")
	}
	nic := &SmartNICInfo{Present: true, BPFSupport: true}
	if !IsAvailable(nic) {
		t.Error("detected SmartNIC should be available")
	}
}

func TestIsAvailableNoBPF(t *testing.T) {
	nic := &SmartNICInfo{Present: true, BPFSupport: false}
	if IsAvailable(nic) {
		t.Error("no BPF support should not be available")
	}
}

func TestIsAvailableNotPresent(t *testing.T) {
	nic := &SmartNICInfo{Present: false, BPFSupport: true}
	if IsAvailable(nic) {
		t.Error("not present should not be available")
	}
}

// ── OffloadConfig edge cases ──────────────────────────────────────

func TestOffloadConfigWithCustomInfo(t *testing.T) {
	tests := []struct {
		name     string
		info     *SmartNICInfo
		wantSock bool
		wantNet  bool
		wantIF   string
	}{
		{"present+bpf+ifaces", &SmartNICInfo{Present: true, BPFSupport: true, Interfaces: []string{"ens1f0"}}, true, true, "ens1f0"},
		{"present+nobpf", &SmartNICInfo{Present: true, BPFSupport: false, Interfaces: []string{"eth0"}}, false, true, "eth0"},
		{"not-present", &SmartNICInfo{Present: false, BPFSupport: false}, false, false, ""},
		{"no-interfaces", &SmartNICInfo{Present: true, BPFSupport: true}, true, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := OffloadConfig(tt.info)
			if cfg.OffloadSocketEvents != tt.wantSock {
				t.Errorf("OffloadSocketEvents = %v, want %v", cfg.OffloadSocketEvents, tt.wantSock)
			}
			if cfg.OffloadNetworkEvents != tt.wantNet {
				t.Errorf("OffloadNetworkEvents = %v, want %v", cfg.OffloadNetworkEvents, tt.wantNet)
			}
			if cfg.NicInterface != tt.wantIF {
				t.Errorf("NicInterface = %q, want %q", cfg.NicInterface, tt.wantIF)
			}
		})
	}
}

// ── GPU tests ───────────────────────────────────────────────

func TestDetectGPU(t *testing.T) {
	gpu := DetectGPU()
	if gpu == nil {
		t.Fatal("DetectGPU returned nil")
	}
	t.Logf("GPU: present=%v driver=%s cuda=%s names=%v",
		gpu.Present, gpu.Driver, gpu.CUDAVersion, gpu.GPUNames)
}

func TestGPUStats(t *testing.T) {
	stats := GPUStats()
	t.Logf("GPU stats: %v", stats)
}

func TestNewClusteringEngine(t *testing.T) {
	engine := NewClusteringEngine(nil)
	if engine == nil {
		t.Fatal("NewClusteringEngine returned nil")
	}
}

func TestExportGraph(t *testing.T) {
	engine := NewClusteringEngine(nil)
	edges := []EdgeRecord{
		{Source: "p:1", Target: "p:2", Weight: 1, Timestamp: 1000},
		{Source: "p:2", Target: "f:100", Weight: 3, Timestamp: 2000},
	}
	path := t.TempDir() + "/export.csv"
	err := engine.ExportGraph(edges, path)
	if err != nil {
		t.Fatalf("ExportGraph: %v", err)
	}
	t.Logf("Exported %d edges to %s", len(edges), path)
}

func TestRunClustering(t *testing.T) {
	engine := NewClusteringEngine(nil)
	clusters, err := engine.RunClustering()
	if err != nil {
		t.Fatalf("RunClustering: %v", err)
	}
	t.Logf("Clusters: %d", len(clusters))
	_ = clusters
}

// ── NVMe tests ─────────────────────────────────────────────

func TestDetectNVMe(t *testing.T) {
	nvme := DetectNVMe()
	if nvme == nil {
		t.Fatal("DetectNVMe returned nil")
	}
	t.Logf("NVMe: present=%v devices=%v model=%s fw=%s",
		nvme.Present, nvme.Devices, nvme.Model, nvme.Firmware)
}

func TestRocksDBConfig(t *testing.T) {
	// With NVMe
	nvme := &NVMeInfo{
		Present: true,
		Devices: []string{"nvme0n1"},
		Model:   "Samsung SSD 980 PRO",
	}
	cfg := RocksDBConfig(nvme)
	if cfg["block_size"].(int) != 64*1024 {
		t.Errorf("NVMe block_size = %d", cfg["block_size"])
	}
	if cfg["use_direct_reads"].(bool) != true {
		t.Error("NVMe should use direct reads")
	}
	t.Logf("NVMe config: block=%d write_buf=%d compactions=%d",
		cfg["block_size"], cfg["write_buffer_size"],
		cfg["max_background_compactions"])

	// Without NVMe
	nvme2 := &NVMeInfo{Present: false}
	cfg2 := RocksDBConfig(nvme2)
	if cfg2["block_size"].(int) != 32*1024 {
		t.Errorf("SATA block_size = %d", cfg2["block_size"])
	}
}

func TestRocksDBConfigNil(t *testing.T) {
	cfg := RocksDBConfig(nil)
	if cfg == nil {
		t.Fatal("nil config")
	}
	if cfg["block_size"].(int) != 32*1024 {
		t.Errorf("default block_size = %d", cfg["block_size"])
	}
}

func TestNVMeOptimize(t *testing.T) {
	err := NVMeOptimize(nil)
	if err != nil {
		t.Errorf("nil NVMe: %v", err)
	}
	err = NVMeOptimize(&NVMeInfo{
		Present: true,
		Devices: []string{"nvme0n1"},
	})
	if err != nil {
		t.Logf("NVMe optimize (may need root): %v", err)
	}
}

// ── DefaultClusteringConfig ─────────────────────────────────────

func TestDefaultClusteringConfig(t *testing.T) {
	cfg := DefaultClusteringConfig()
	if cfg == nil {
		t.Fatal("nil config")
	}
	if cfg.ExportPath != "/var/lib/providapt/export" {
		t.Errorf("ExportPath = %q", cfg.ExportPath)
	}
	if cfg.MinClusterSize != 10 {
		t.Errorf("MinClusterSize = %d", cfg.MinClusterSize)
	}
	if cfg.Algorithm != "louvain" {
		t.Errorf("Algorithm = %q", cfg.Algorithm)
	}
	if !cfg.UseCUDA {
		t.Error("UseCUDA should be true by default")
	}
}

// ── NewClusteringEngine config ────────────────────────────────────

func TestNewClusteringEngineCustomConfig(t *testing.T) {
	cfg := &GraphClusteringConfig{
		ExportPath:     t.TempDir(),
		MinClusterSize: 5,
		Algorithm:      "kmeans",
		UseCUDA:        false,
	}
	engine := NewClusteringEngine(cfg)
	if engine == nil {
		t.Fatal("nil engine")
	}
	// Verify the engine uses the custom config (MinClusterSize is a simple check)
	if engine.cfg.MinClusterSize != 5 {
		t.Errorf("MinClusterSize = %d, want 5", engine.cfg.MinClusterSize)
	}
	if engine.cfg.Algorithm != "kmeans" {
		t.Errorf("Algorithm = %q", engine.cfg.Algorithm)
	}
}

// ── ExportGraph content verification ─────────────────────────────

func TestExportGraphEmptyEdges(t *testing.T) {
	engine := NewClusteringEngine(&GraphClusteringConfig{ExportPath: t.TempDir()})
	path := t.TempDir() + "/empty.csv"
	err := engine.ExportGraph(nil, path)
	if err != nil {
		t.Fatalf("ExportGraph(nil): %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// CSV should have header but no data rows
	content := string(data)
	if !strings.HasPrefix(content, "source,target,weight,timestamp\n") {
		t.Errorf("bad header: %q", content)
	}
	if strings.Count(content, "\n") != 1 {
		t.Errorf("expected 1 line (header only), got %d lines", strings.Count(content, "\n"))
	}
}

func TestExportGraphCSVFormat(t *testing.T) {
	engine := NewClusteringEngine(&GraphClusteringConfig{ExportPath: t.TempDir()})
	edges := []EdgeRecord{
		{Source: "p:1", Target: "p:2", Weight: 1, Timestamp: 1000},
		{Source: "p:2", Target: "f:100", Weight: 3, Timestamp: 2000},
	}
	path := t.TempDir() + "/verify.csv"
	if err := engine.ExportGraph(edges, path); err != nil {
		t.Fatalf("ExportGraph: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "p:1,p:2,1,1000") {
		t.Errorf("missing first edge: %q", content)
	}
	if !strings.Contains(content, "p:2,f:100,3,2000") {
		t.Errorf("missing second edge: %q", content)
	}
}

// ── RocksDBConfig edge cases ──────────────────────────────────────

func TestRocksDBConfigPresentNoDevices(t *testing.T) {
	// Present=true but empty Devices — should still apply NVMe config
	nvme := &NVMeInfo{Present: true}
	cfg := RocksDBConfig(nvme)
	if cfg["block_size"].(int) != 64*1024 {
		t.Errorf("block_size = %d, want NVMe 64KB", cfg["block_size"])
	}
	if cfg["use_direct_reads"].(bool) != true {
		t.Error("NVMe should use direct reads")
	}
}

func TestRocksDBConfigAllKeys(t *testing.T) {
	// Verify all expected keys exist in NVMe config
	nvme := &NVMeInfo{Present: true, Devices: []string{"nvme0n1"}, Model: "Test"}
	cfg := RocksDBConfig(nvme)
	expectedKeys := []string{
		"block_size", "write_buffer_size", "max_write_buffer_number",
		"min_write_buffer_number", "max_background_compactions",
		"max_background_flushes", "bytes_per_sync", "use_direct_reads",
		"use_direct_io_for_flush_and_compaction", "compaction_readahead_size",
	}
	for _, k := range expectedKeys {
		if _, ok := cfg[k]; !ok {
			t.Errorf("missing key: %s", k)
		}
	}
}

func TestRocksDBConfigSATAKeys(t *testing.T) {
	// Verify no NVMe-specific keys in SATA config
	nvme := &NVMeInfo{Present: false}
	cfg := RocksDBConfig(nvme)
	if _, ok := cfg["compaction_readahead_size"]; ok {
		t.Error("SATA config should not have compaction_readahead_size")
	}
}

// ── Integration test ────────────────────────────────────────

func TestHWAccelIntegration(t *testing.T) {
	t.Log("=== HW Acceleration Probe ===")

	// SmartNIC
	nic := DetectSmartNIC()
	t.Logf("SmartNIC: %s", ternary(nic.Present, nic.Model, "not detected"))

	// GPU
	gpu := DetectGPU()
	t.Logf("GPU: %s", ternary(gpu.Present,
		fmt.Sprintf("%v (%s)", gpu.GPUNames, gpu.Driver), "not detected"))
	_ = gpu

	// NVMe
	nvme := DetectNVMe()
	t.Logf("NVMe: %s", ternary(nvme.Present,
		fmt.Sprintf("%s (%s)", nvme.Model, nvme.Firmware), "not detected"))

	// Config generation
	rocksCfg := RocksDBConfig(nvme)
	t.Logf("RocksDB: block_size=%d max_compactions=%d",
		rocksCfg["block_size"], rocksCfg["max_background_compactions"])

	t.Log("=== HW Acceleration Probe Complete ===")
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
