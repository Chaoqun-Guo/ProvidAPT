// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/probe"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/profile"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
)

type pinnedMapInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type bpfReport struct {
	Probe      *probe.Result     `json:"probe"`
	Programs   *profile.BPFStats `json:"programs,omitempty"`
	PinnedMaps []pinnedMapInfo   `json:"pinned_maps,omitempty"`
}

func cmdBPF(jsonOut bool) {
	pr := probe.Probe()

	bpfStats, _ := profile.CollectBPFStats()

	var pinned []pinnedMapInfo
	if entries, err := os.ReadDir("/sys/fs/bpf/providapt/"); err == nil {
		for _, e := range entries {
			pinned = append(pinned, pinnedMapInfo{
				Name: e.Name(),
				Path: filepath.Join("/sys/fs/bpf/providapt/", e.Name()),
			})
		}
	}

	if jsonOut {
		clioutput.PrintJSON(bpfReport{
			Probe:      pr,
			Programs:   bpfStats,
			PinnedMaps: pinned,
		})
		return
	}

	fmt.Println(clioutput.Bold("Kernel Capabilities"))
	t1 := clioutput.NewTable("Property", "Value")
	t1.AddRow("Kernel Version", pr.KernelVer)
	t1.AddRow("Detected Mode", pr.ModeName)
	t1.AddRow("BTF Available", fmt.Sprintf("%v", pr.BTFAvailable))
	t1.AddRow("BPF LSM", fmt.Sprintf("%v", pr.BpfLSM))
	t1.AddRow("Has Fentry", fmt.Sprintf("%v", pr.HasFentry))
	t1.AddRow("Has Kprobe", fmt.Sprintf("%v", pr.HasKprobe))
	if pr.Reason != "" {
		t1.AddRow("Reason", pr.Reason)
	}
	t1.Render()
	fmt.Println()

	if bpfStats != nil && len(bpfStats.Programs) > 0 {
		fmt.Println(clioutput.Bold("eBPF Programs"))
		t2 := clioutput.NewTable("ID", "Name", "Type", "Runs", "Avg Time")
		for _, p := range bpfStats.Programs {
			avg := fmt.Sprintf("%.2fµs", p.AvgRunNS/1000)
			t2.AddRow(
				fmt.Sprintf("%d", p.ID),
				p.Name,
				p.Type,
				fmt.Sprintf("%d", p.RunCount),
				avg,
			)
		}
		t2.Render()
		fmt.Println()
	} else {
		fmt.Println(clioutput.Warnf("No eBPF programs found (bpftool may not be available or daemon not running)"))
		fmt.Println()
	}

	if len(pinned) > 0 {
		fmt.Println(clioutput.Bold("Pinned Maps"))
		t3 := clioutput.NewTable("Name", "Path")
		for _, m := range pinned {
			t3.AddRow(m.Name, m.Path)
		}
		t3.Render()
	} else {
		fmt.Println(clioutput.Warnf("No pinned maps found at /sys/fs/bpf/providapt/"))
	}
}
