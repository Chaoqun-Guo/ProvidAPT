// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package plugin

// discoverPlugins is a stub for non-Unix platforms (Windows).
// The Go plugin package is only supported on Linux and macOS.
func discoverPlugins(dir string) (*DiscoveryResult, error) {
	return nil, ErrUnsupported
}
