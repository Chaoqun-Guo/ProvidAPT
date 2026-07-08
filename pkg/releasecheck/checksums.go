package releasecheck

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode"
)

func checkChecksums(report *Report, path string) {
	if strings.TrimSpace(path) == "" {
		return
	}

	file, err := os.Open(path)
	if err != nil {
		add(report, Check{
			Name:          "release_checksums",
			Status:        StatusWarn,
			Message:       fmt.Sprintf("checksums file unavailable: %v", err),
			FixSuggestion: "Generate dist/checksums.txt during the release build and pass it with -release-checksums.",
		})
		return
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	entries := 0
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			add(report, Check{
				Name:          "release_checksums",
				Status:        StatusFail,
				Message:       fmt.Sprintf("checksums line %d must contain sha256 and artifact name", lineNo),
				FixSuggestion: "Use GoReleaser checksums format: <64-char sha256>  <artifact>.",
			})
			return
		}
		if !isSHA256Hex(fields[0]) {
			add(report, Check{
				Name:          "release_checksums",
				Status:        StatusFail,
				Message:       fmt.Sprintf("checksums line %d has invalid SHA-256 digest", lineNo),
				FixSuggestion: "Regenerate checksums.txt from the release artifacts.",
			})
			return
		}
		if strings.TrimSpace(fields[1]) == "" {
			add(report, Check{
				Name:          "release_checksums",
				Status:        StatusFail,
				Message:       fmt.Sprintf("checksums line %d has an empty artifact name", lineNo),
				FixSuggestion: "Ensure every checksum entry names the artifact it verifies.",
			})
			return
		}
		entries++
	}
	if err := scanner.Err(); err != nil {
		add(report, Check{
			Name:          "release_checksums",
			Status:        StatusFail,
			Message:       fmt.Sprintf("cannot read checksums file: %v", err),
			FixSuggestion: "Fix filesystem permissions or regenerate checksums.txt.",
		})
		return
	}
	if entries == 0 {
		add(report, Check{
			Name:          "release_checksums",
			Status:        StatusFail,
			Message:       "checksums file contains no artifact entries",
			FixSuggestion: "Regenerate checksums.txt after release artifacts are built.",
		})
		return
	}

	add(report, Check{
		Name:    "release_checksums",
		Status:  StatusPass,
		Message: fmt.Sprintf("checksums file contains %d artifact entries", entries),
	})
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range value {
		if !unicode.IsDigit(ch) && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}
