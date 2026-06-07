// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/profile"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
)

func cmdProfile(jsonOut bool) {
	clioutput.Printf("%s\n", clioutput.Infof("Collecting performance profile..."))

	report := profile.CollectProfile(nil)

	if jsonOut {
		clioutput.PrintJSON(report)
		return
	}

	fmt.Println(clioutput.Bold("Performance Profile"))
	fmt.Println()
	fmt.Printf("Timestamp: %s\n", report.Timestamp)
	fmt.Println()

	if report.System != nil {
		fmt.Println(clioutput.Bold("System Resources"))
		t1 := clioutput.NewTable("Metric", "Value")
		t1.AddRow("CPU Usage", fmt.Sprintf("%.1f%%", report.System.CPUPercent))
		t1.AddRow("Memory RSS", fmt.Sprintf("%.0f MB", report.System.MemoryRSSMB))
		t1.AddRow("Memory VM", fmt.Sprintf("%.0f MB", report.System.MemoryVMMB))
		t1.AddRow("Goroutines", fmt.Sprintf("%d", report.System.Goroutines))
		t1.AddRow("Go Version", report.System.GoVersion)
		t1.AddRow("Open FDs", fmt.Sprintf("%d", report.System.FDCount))
		t1.Render()
		fmt.Println()
	}

	if report.BPF != nil && len(report.BPF.Programs) > 0 {
		fmt.Println(clioutput.Bold("eBPF Programs"))
		t2 := clioutput.NewTable("ID", "Name", "Type", "Runs", "Avg Time")
		for _, p := range report.BPF.Programs {
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
	}

	if len(report.Storage) > 0 {
		fmt.Println(clioutput.Bold("Storage"))
		t3 := clioutput.NewTable("Metric", "Value")
		for k, v := range report.Storage {
			t3.AddRow(k, fmt.Sprintf("%v", v))
		}
		t3.Render()
		fmt.Println()
	}

	fmt.Printf("Profile collected in %s\n", report.Duration)
}
