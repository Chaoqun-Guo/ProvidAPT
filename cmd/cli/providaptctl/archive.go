// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/archive"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

func cmdArchive(cfgPath, inputDir string, ageDays int, dryRun bool) {
	if inputDir == "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			clioutput.Fatalf("Config load failed: %v", err)
		}
		inputDir = cfg.Output.Dir
	}

	age := time.Duration(ageDays) * 24 * time.Hour

	clioutput.Printf("%s\n", clioutput.Infof("Archiving events older than %d days from %s...", ageDays, inputDir))

	res, err := archive.Run(archive.Option{
		InputDir: inputDir,
		Age:      age,
		DryRun:   dryRun,
	})
	if err != nil {
		clioutput.Fatalf("Archive failed: %v", err)
	}

	if clioutput.IsJSONMode() {
		clioutput.PrintJSON(res)
		return
	}

	if res.FilesArchived == 0 {
		clioutput.Printf("%s\n", clioutput.Infof("No files to archive"))
		return
	}

	fmt.Println(clioutput.Bold("Archive Results"))
	fmt.Println()

	t := clioutput.NewTable("Metric", "Value")
	t.AddRow("Input Directory", res.InputDir)
	t.AddRow("Files Archived", fmt.Sprintf("%d", res.FilesArchived))
	t.AddRow("Files Skipped", fmt.Sprintf("%d", res.FilesSkipped))
	t.AddRow("Bytes Before", fmt.Sprintf("%d", res.BytesBefore))
	t.AddRow("Bytes After", fmt.Sprintf("%d", res.BytesAfter))
	t.AddRow("Duration", res.Duration.Round(time.Millisecond).String())
	if res.DryRun {
		t.AddRow("Dry Run", "true (no data was archived)")
	}
	if res.ArchivePath != "" {
		t.AddRow("Archive", res.ArchivePath)
	}
	t.Render()
}
