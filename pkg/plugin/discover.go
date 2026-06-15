// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package plugin

import (
	"log"
	"os"
	"path/filepath"
	goplugin "plugin"
	"strings"
)

// discoverPlugins scans dir for .so files, loads each one, and calls
// the exported RegisterPlugins() function to auto-register types.
func discoverPlugins(dir string) (*DiscoveryResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	result := &DiscoveryResult{}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".so") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		if err := loadPlugin(path); err != nil {
			log.Printf("[plugin] discover %s: %v", entry.Name(), err)
			result.Failed = append(result.Failed, path)
			continue
		}
		result.Loaded = append(result.Loaded, entry.Name())
		log.Printf("[plugin] loaded: %s", entry.Name())
	}

	return result, nil
}

// loadPlugin opens a single .so file and calls RegisterPlugins.
func loadPlugin(path string) error {
	p, err := goplugin.Open(path)
	if err != nil {
		return err
	}

	sym, err := p.Lookup("RegisterPlugins")
	if err != nil {
		return err
	}

	regFn, ok := sym.(func())
	if !ok {
		return nil // no-op: plugin doesn't use auto-registration
	}

	regFn()
	return nil
}
