// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/replay"
)

func cmdReplay(cfgPath, inputDir string, maxEvents int) {
	if inputDir == "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			clioutput.Fatalf("Config load failed: %v", err)
		}
		inputDir = cfg.Output.Dir
	}

	clioutput.Printf("%s\n", clioutput.Infof("Replaying events from %s...", inputDir))

	res, graph := replay.Run(replay.Option{
		InputDir:  inputDir,
		MaxEvents: maxEvents,
	})

	if clioutput.IsJSONMode() {
		clioutput.PrintJSON(res)
		return
	}

	fmt.Println(clioutput.Bold("Event Replay Results"))
	fmt.Println()

	t := clioutput.NewTable("Metric", "Value")
	t.AddRow("Input Directory", res.Dir)
	t.AddRow("Files Read", fmt.Sprintf("%d", res.FilesRead))
	t.AddRow("Events Read", fmt.Sprintf("%d", res.EventsRead))
	t.AddRow("Events Ingested", fmt.Sprintf("%d", res.EventsOK))
	t.AddRow("Events Skipped", fmt.Sprintf("%d", res.EventsSkip))
	t.AddRow("Graph Nodes", fmt.Sprintf("%d", res.Nodes))
	t.AddRow("Graph Edges", fmt.Sprintf("%d", res.Edges))
	t.AddRow("Duration", res.Duration.Round(time.Millisecond).String())
	t.Render()

	if res.Error != "" {
		fmt.Println()
		clioutput.Printf("%s\n", clioutput.Warnf("Warning: %s", res.Error))
	}

	// Show graph contents if events were loaded
	if res.EventsOK > 0 && graph != nil {
		fmt.Println()
		fmt.Println(clioutput.Bold("Recent Nodes (top 10)"))
		t2 := clioutput.NewTable("ID", "Label", "Type")
		count := 0
		for _, n := range graph.Nodes() {
			if count >= 10 {
				break
			}
			t2.AddRow(n.ID, n.Label, n.ProvType)
			count++
		}
		t2.Render()
	}
}
