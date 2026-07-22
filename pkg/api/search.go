// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EventRecord is a minimal search result from the event log.
type EventRecord struct {
	Timestamp string                 `json:"timestamp,omitempty"`
	PID       uint32                 `json:"pid,omitempty"`
	Comm      string                 `json:"comm,omitempty"`
	Type      string                 `json:"type,omitempty"`
	Subtype   string                 `json:"subtype,omitempty"`
	Label     string                 `json:"label,omitempty"`
	Raw       map[string]interface{} `json:"raw,omitempty"`
}

// SearchResult wraps paginated search results.
type SearchResult struct {
	Total   int           `json:"total"`
	Results []EventRecord `json:"results"`
	Limit   int           `json:"limit"`
	Offset  int           `json:"offset"`
	Time    string        `json:"time,omitempty"`
}

// SearchParams captures filters from the HTTP query string.
type SearchParams struct {
	Pattern  string // substring match on event type/label
	Severity string // severity filter (INFO, LOW, MEDIUM, HIGH, CRITICAL)
	Since    string // RFC3339 start time
	Until    string // RFC3339 end time
	Limit    int    // max results (default 100)
	Offset   int    // pagination offset
}

// handleEventSearch searches event logs and alert files.

func (s *Server) handleEventSearch(w http.ResponseWriter, r *http.Request) error {
	params := SearchParams{
		Pattern:  r.URL.Query().Get("pattern"),
		Severity: r.URL.Query().Get("severity"),
		Since:    r.URL.Query().Get("since"),
		Until:    r.URL.Query().Get("until"),
		Limit:    queryInt(r, "limit", 100),
		Offset:   queryInt(r, "offset", 0),
	}

	if params.Limit <= 0 || params.Limit > 1000 {
		params.Limit = 100
	}
	if params.Offset < 0 {
		params.Offset = 0
	}

	outDir := resolveOutputDir()
	results, err := searchEvents(outDir, params)
	if err != nil {
		return fmt.Errorf("search events: %w", err)
	}

	result := SearchResult{
		Total:   len(results),
		Results: results,
		Limit:   params.Limit,
		Offset:  params.Offset,
		Time:    time.Now().UTC().Format(time.RFC3339),
	}

	// Apply pagination
	if params.Offset > 0 || len(results) > params.Limit {
		start := params.Offset
		if start > len(results) {
			start = len(results)
		}
		end := start + params.Limit
		if end > len(results) {
			end = len(results)
		}
		result.Results = results[start:end]
		result.Total = len(results)
	}

	return json.NewEncoder(w).Encode(result)
}

// handleEventRecent returns the most recent events across all log files.

func (s *Server) handleEventRecent(w http.ResponseWriter, r *http.Request) error {
	limit := queryInt(r, "limit", 50)
	if limit <= 0 || limit > 1000 {
		limit = 50
	}

	outDir := resolveOutputDir()
	results, err := recentEvents(outDir, limit)
	if err != nil {
		return fmt.Errorf("recent events: %w", err)
	}

	return json.NewEncoder(w).Encode(SearchResult{
		Total:   len(results),
		Results: results,
		Limit:   limit,
		Time:    time.Now().UTC().Format(time.RFC3339),
	})
}

func searchEvents(dir string, p SearchParams) ([]EventRecord, error) {
	files, err := findSearchFiles(dir)
	if err != nil {
		return nil, err
	}

	results := []EventRecord{}
	for _, f := range files {
		recs, err := searchFile(f, p)
		if err != nil {
			continue // skip unreadable files
		}
		results = append(results, recs...)
		if len(results) > p.Limit+p.Offset+1000 {
			break // safety cap
		}
	}
	return results, nil
}

func recentEvents(dir string, limit int) ([]EventRecord, error) {
	files, err := findEventFiles(dir)
	if err != nil {
		return nil, err
	}

	results := []EventRecord{}
	// Read files in reverse order (most recent first)
	for i := len(files) - 1; i >= 0; i-- {
		recs, err := tailFile(files[i], limit-len(results))
		if err != nil {
			continue
		}
		results = append(results, recs...)
		if len(results) >= limit {
			break
		}
	}
	return results, nil
}

func findEventFiles(dir string) ([]string, error) {
	return findLogFiles(dir, false)
}

func findSearchFiles(dir string) ([]string, error) {
	return findLogFiles(dir, true)
}

func findLogFiles(dir string, includeAlerts bool) ([]string, error) {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "providapt-") &&
			(strings.HasSuffix(name, ".ndjson") || strings.HasSuffix(name, ".json")) {
			files = append(files, filepath.Join(dir, name))
			continue
		}
		if includeAlerts && (name == "alerts.ndjson" || (strings.HasPrefix(name, "alerts-") && strings.HasSuffix(name, ".ndjson"))) {
			files = append(files, filepath.Join(dir, name))
		}
	}
	return files, nil
}

func searchFile(path string, p SearchParams) ([]EventRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	results := []EventRecord{}
	scanner := bufio.NewScanner(f)
	// Use a larger buffer for potentially long lines
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}

		// Apply filters
		if !matchFilters(raw, p) {
			continue
		}

		rec := mapToRecord(raw)
		if p.Pattern == "" || recordMatches(rec, p.Pattern) {
			results = append(results, rec)
		}

		if len(results) > p.Limit+p.Offset+1000 {
			break
		}
	}
	return results, scanner.Err()
}

func tailFile(path string, n int) ([]EventRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var lines [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	for scanner.Scan() {
		b := make([]byte, len(scanner.Bytes()))
		copy(b, scanner.Bytes())
		lines = append(lines, b)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	start := 0
	if len(lines) > n {
		start = len(lines) - n
	}

	results := []EventRecord{}
	for _, line := range lines[start:] {
		if len(line) == 0 {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}
		results = append(results, mapToRecord(raw))
	}
	return results, nil
}

func matchFilters(raw map[string]interface{}, p SearchParams) bool {
	// Severity filter (alerts only)
	if p.Severity != "" {
		sev, _ := raw["severity"].(string)
		if !strings.EqualFold(sev, p.Severity) {
			return false
		}
	}

	// Time range filters
	if p.Since != "" || p.Until != "" {
		ts, _ := raw["timestamp_ns"].(float64)
		if ts == 0 {
			tsStr, _ := raw["timestamp"].(string)
			if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
				ts = float64(t.UnixNano())
			}
		}

		if p.Since != "" {
			since, err := time.Parse(time.RFC3339, p.Since)
			if err == nil && ts > 0 && int64(ts) < since.UnixNano() {
				return false
			}
		}
		if p.Until != "" {
			until, err := time.Parse(time.RFC3339, p.Until)
			if err == nil && ts > 0 && int64(ts) > until.UnixNano() {
				return false
			}
		}
	}

	return true
}

func recordMatches(rec EventRecord, pattern string) bool {
	if pattern == "" {
		return true
	}
	pattern = strings.ToLower(pattern)
	return strings.Contains(strings.ToLower(rec.Comm), pattern) ||
		strings.Contains(strings.ToLower(rec.Label), pattern) ||
		strings.Contains(strings.ToLower(rec.Type), pattern) ||
		strings.Contains(strings.ToLower(rec.Subtype), pattern) ||
		strings.Contains(strings.ToLower(fmt.Sprint(rec.Raw)), pattern)
}

func mapToRecord(raw map[string]interface{}) EventRecord {
	rec := EventRecord{Raw: raw}

	if ts, ok := raw["timestamp_ns"].(float64); ok {
		rec.Timestamp = time.Unix(0, int64(ts)).UTC().Format(time.RFC3339Nano)
	} else if ts, ok := raw["timestamp"].(string); ok {
		rec.Timestamp = ts
	}

	if pid, ok := raw["pid"].(float64); ok {
		rec.PID = uint32(pid)
	}
	if comm, ok := raw["comm"].(string); ok {
		rec.Comm = comm
	}
	if process, ok := raw["process"].(map[string]interface{}); ok {
		if pid, ok := process["pid"].(float64); ok {
			rec.PID = uint32(pid)
		}
		if comm, ok := process["comm"].(string); ok {
			rec.Comm = comm
		}
		if rec.Label == "" {
			if exe, ok := process["exe_path"].(string); ok {
				rec.Label = exe
			}
		}
	}
	if t, ok := raw["type"].(string); ok {
		rec.Type = t
	}
	if rec.Type == "" {
		if ruleID, ok := raw["rule_id"].(string); ok && strings.TrimSpace(ruleID) != "" {
			rec.Type = "alert"
		}
	}
	if st, ok := raw["subtype"].(string); ok {
		rec.Subtype = st
	}
	if lbl, ok := raw["label"].(string); ok {
		rec.Label = lbl
	}
	if rec.Label == "" {
		for _, key := range []string{"message", "pattern", "rule_id", "alert_id", "status"} {
			if value, ok := raw[key].(string); ok && strings.TrimSpace(value) != "" {
				rec.Label = value
				break
			}
		}
	}
	if payload, ok := raw["payload"].(map[string]interface{}); ok {
		if payloadLabel := eventPayloadLabel(payload); payloadLabel != "" {
			rec.Label = payloadLabel
		}
		if rec.Subtype == "" {
			if kind, ok := payload["kind"].(string); ok {
				rec.Subtype = kind
			}
		}
	}

	return rec
}

func eventPayloadLabel(payload map[string]interface{}) string {
	for _, key := range []string{"pathname", "exe_path", "cmdline", "address", "dst_addr", "src_addr"} {
		if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	if dst, ok := payload["dst_port"].(float64); ok {
		return fmt.Sprintf("network port %.0f", dst)
	}
	if child, ok := payload["child_pid"].(float64); ok {
		return fmt.Sprintf("child pid %.0f", child)
	}
	return ""
}

func resolveOutputDir() string {
	if dir := strings.TrimSpace(os.Getenv("PROVIDAPT_OUTPUT_DIR")); dir != "" {
		return dir
	}
	return "/var/log/providapt"
}
