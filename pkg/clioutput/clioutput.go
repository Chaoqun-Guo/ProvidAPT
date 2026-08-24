// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package clioutput provides shared CLI output formatting for ProvidAPT tools:
// branded banner, ANSI color helpers, structured JSON output, and table rendering.
package clioutput

import (
	"encoding/json"
	"fmt"
	"os"
)

var (
	jsonMode = false
	colorsOn = true
)

// Init initialises the output package. Call once at program start.
func Init(json bool) {
	jsonMode = json
	// Disable colours when stdout is not a terminal (pipe/redirect)
	if stat, err := os.Stdout.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		colorsOn = false
	}
}

// IsJSONMode reports whether JSON output mode is active.
func IsJSONMode() bool { return jsonMode }

// ── Banner ──

const banner = "╔═══════════════════════════════════════════════════════════════════╗\n║                    ProvidAPT v%-28s ║\n║          Provenance-driven APT Detection Platform            ║\n╚═══════════════════════════════════════════════════════════════════╝"

// PrintBanner writes the product banner to stderr. No-op in JSON mode.
func PrintBanner(version string) {
	if jsonMode {
		return
	}
	fmt.Fprintf(os.Stderr, banner+"\n", version)
}

// ── Colour helpers ──

func colorize(code, s string) string {
	if !colorsOn || jsonMode {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

// Infof returns a cyan-coloured string (informational).
func Infof(format string, args ...interface{}) string {
	return colorize("36", fmt.Sprintf(format, args...))
}

// Warnf returns a yellow-coloured string (warning).
func Warnf(format string, args ...interface{}) string {
	return colorize("33", fmt.Sprintf(format, args...))
}

// Errf returns a red-coloured string (error).
func Errf(format string, args ...interface{}) string {
	return colorize("31", fmt.Sprintf(format, args...))
}

// Okf returns a green-coloured string (success).
func Okf(format string, args ...interface{}) string {
	return colorize("32", fmt.Sprintf(format, args...))
}

// Bold returns the string wrapped in ANSI bold.
func Bold(s string) string {
	return colorize("1", s)
}

// ── Print helpers ──

// PrintJSON writes v as indented JSON to stdout followed by a newline.
func PrintJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// Fatalf prints a red error message to stderr and exits with code 1.
func Fatalf(format string, args ...interface{}) {
	fmt.Fprintln(os.Stderr, colorize("31", fmt.Sprintf(format, args...)))
	os.Exit(1)
}

// Printf writes directly to stdout (pass-through for non-coloured output).
func Printf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format, args...)
}
