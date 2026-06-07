// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/backup"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

// cmdBackup creates a backup archive of the Pebble store.
func cmdBackup(cfgPath, outputPath string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		clioutput.Fatalf("config load failed: %v", err)
	}

	storePath := filepath.Join(cfg.Output.Dir, "store")
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		clioutput.Fatalf("store not found at %s", storePath)
	}

	if outputPath == "" {
		timestamp := time.Now().UTC().Format("20060102T150405")
		outputPath = filepath.Join(cfg.Output.Dir, fmt.Sprintf("providapt-backup-%s.tar.gz", timestamp))
	}

	clioutput.Printf("%s\n", clioutput.Infof("Creating backup of %s → %s ...", storePath, outputPath))

	meta, err := backup.Create(storePath, outputPath)
	if err != nil {
		clioutput.Fatalf("backup failed: %v", err)
	}

	clioutput.Printf("%s\n", clioutput.Okf("Backup created"))
	t := clioutput.NewTable("Field", "Value")
	t.AddRow("Path", meta.Path)
	t.AddRow("Size", formatBytes(meta.SizeBytes))
	t.AddRow("Store", meta.StorePath)
	t.Render()
}

// cmdRestore restores the store from a backup archive.
func cmdRestore(cfgPath, inputPath string) {
	if inputPath == "" {
		clioutput.Fatalf("-restore-in flag required")
	}
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		clioutput.Fatalf("backup file not found: %s", inputPath)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		clioutput.Fatalf("config load failed: %v", err)
	}

	storePath := filepath.Join(cfg.Output.Dir, "store")
	clioutput.Printf("%s\n", clioutput.Warnf("Restoring backup %s → %s ...", inputPath, storePath))
	clioutput.Printf("%s\n", clioutput.Warnf("Make sure the daemon is stopped before restoring!"))

	if err := backup.Restore(inputPath, storePath); err != nil {
		clioutput.Fatalf("restore failed: %v", err)
	}
	clioutput.Printf("%s\n", clioutput.Okf("Restore complete"))
}
