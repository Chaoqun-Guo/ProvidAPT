package releasecheck

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type waiverFile struct {
	Waivers []Waiver `json:"waivers"`
}

func applyWaivers(report *Report, path string) {
	if strings.TrimSpace(path) == "" {
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		add(report, Check{
			Name:          "release_waivers",
			Status:        StatusFail,
			Message:       fmt.Sprintf("release waiver file unavailable: %v", err),
			FixSuggestion: "Provide a readable JSON waiver file or omit -release-waivers.",
		})
		return
	}

	var file waiverFile
	if err := json.Unmarshal(data, &file); err != nil {
		add(report, Check{
			Name:          "release_waivers",
			Status:        StatusFail,
			Message:       fmt.Sprintf("release waiver file is invalid JSON: %v", err),
			FixSuggestion: "Write waivers as {\"waivers\":[{\"check\":\"api_auth\",\"reason\":\"...\",\"approved_by\":\"...\"}]}.",
		})
		return
	}

	waivers := make(map[string]Waiver, len(file.Waivers))
	for _, waiver := range file.Waivers {
		checkName := strings.TrimSpace(waiver.Check)
		if checkName == "" || strings.TrimSpace(waiver.Reason) == "" || strings.TrimSpace(waiver.ApprovedBy) == "" {
			add(report, Check{
				Name:          "release_waivers",
				Status:        StatusFail,
				Message:       "waiver entries require check, reason, and approved_by",
				FixSuggestion: "Complete every waiver entry before commercial sign-off.",
			})
			return
		}
		if waiver.Expires != "" {
			expires, err := time.Parse("2006-01-02", waiver.Expires)
			if err != nil {
				add(report, Check{
					Name:          "release_waivers",
					Status:        StatusFail,
					Message:       fmt.Sprintf("waiver %q has invalid expires date %q", checkName, waiver.Expires),
					FixSuggestion: "Use YYYY-MM-DD waiver expiry dates.",
				})
				return
			}
			today := time.Date(report.GeneratedAt.Year(), report.GeneratedAt.Month(), report.GeneratedAt.Day(), 0, 0, 0, 0, time.UTC)
			if expires.Before(today) {
				add(report, Check{
					Name:          "release_waivers",
					Status:        StatusFail,
					Message:       fmt.Sprintf("waiver %q expired on %s", checkName, waiver.Expires),
					FixSuggestion: "Renew the waiver approval or fix the underlying release check.",
				})
				return
			}
		}
		waiver.Check = checkName
		waivers[checkName] = waiver
	}

	applied := make(map[string]bool, len(waivers))
	for index := range report.Checks {
		check := &report.Checks[index]
		waiver, ok := waivers[check.Name]
		if !ok || check.Status != StatusWarn {
			continue
		}
		check.Status = StatusWaived
		check.Waiver = &waiver
		check.FixSuggestion = ""
		report.Warnings--
		report.Waived++
		applied[check.Name] = true
	}

	for checkName := range waivers {
		if !applied[checkName] {
			add(report, Check{
				Name:          "release_waivers",
				Status:        StatusWarn,
				Message:       fmt.Sprintf("waiver %q did not match an active warning", checkName),
				FixSuggestion: "Remove stale waivers or confirm the intended check name.",
			})
		}
	}
}
