// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package logx

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	mu           sync.RWMutex
	systemLogger *slog.Logger
	auditLogger  *slog.Logger
	debugLogger  *slog.Logger
	currentLevel slog.Level
	jsonFormat   bool
)

func init() {
	Init("info", "text")
}

// Init configures all three loggers. level is one of debug, info, warn, error.
// format is text or json. Output always goes to stderr.
func Init(level, format string) {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "info":
		l = slog.LevelInfo
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}

	var h slog.Handler
	opts := &slog.HandlerOptions{Level: l}
	w := os.Stderr

	switch strings.ToLower(format) {
	case "json":
		h = slog.NewJSONHandler(w, opts)
		jsonFormat = true
	default:
		h = slog.NewTextHandler(w, opts)
		jsonFormat = false
	}

	base := slog.New(h)

	mu.Lock()
	currentLevel = l
	systemLogger = base.With("category", "system")
	auditLogger = base.With("category", "audit")
	debugLogger = base.With("category", "debug")
	mu.Unlock()
}

// SetOutput redirects the underlying handler output to w. Used in tests.
func SetOutput(w io.Writer) {
	mu.RLock()
	l := currentLevel
	jsonFmt := jsonFormat
	mu.RUnlock()

	opts := &slog.HandlerOptions{Level: l}
	var newH slog.Handler
	if jsonFmt {
		newH = slog.NewJSONHandler(w, opts)
	} else {
		newH = slog.NewTextHandler(w, opts)
	}
	base := slog.New(newH)

	mu.Lock()
	systemLogger = base.With("category", "system")
	auditLogger = base.With("category", "audit")
	debugLogger = base.With("category", "debug")
	mu.Unlock()
}

func System() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return systemLogger
}

func Audit() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return auditLogger
}

func Debug() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return debugLogger
}
