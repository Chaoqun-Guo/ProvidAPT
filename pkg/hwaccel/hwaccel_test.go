package hwaccel

import (
	"fmt"
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
