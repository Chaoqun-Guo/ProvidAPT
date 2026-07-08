package releasecheck

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type sbomDocument struct {
	SPDXVersion string            `json:"spdxVersion"`
	Packages    []json.RawMessage `json:"packages"`
	BOMFormat   string            `json:"bomFormat"`
	SpecVersion string            `json:"specVersion"`
	Components  []json.RawMessage `json:"components"`
}

func checkSBOMs(report *Report, paths []string) {
	paths = cleanPathList(paths)
	if len(paths) == 0 {
		return
	}

	recognized := 0
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			add(report, Check{
				Name:          "release_sbom",
				Status:        StatusWarn,
				Message:       fmt.Sprintf("SBOM file %q unavailable: %v", path, err),
				FixSuggestion: "Generate SPDX or CycloneDX SBOM artifacts during release and pass them with -release-sbom.",
			})
			continue
		}

		var doc sbomDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			add(report, Check{
				Name:          "release_sbom",
				Status:        StatusFail,
				Message:       fmt.Sprintf("SBOM file %q is invalid JSON: %v", path, err),
				FixSuggestion: "Regenerate the SBOM as SPDX JSON or CycloneDX JSON.",
			})
			return
		}

		format, entries, ok := classifySBOM(doc)
		if !ok {
			add(report, Check{
				Name:          "release_sbom",
				Status:        StatusFail,
				Message:       fmt.Sprintf("SBOM file %q is not recognized as SPDX or CycloneDX JSON", path),
				FixSuggestion: "Provide an SPDX JSON document with spdxVersion or a CycloneDX JSON document with bomFormat.",
			})
			return
		}
		recognized++
		add(report, Check{
			Name:    "release_sbom",
			Status:  StatusPass,
			Message: fmt.Sprintf("%s SBOM %q contains %d inventory entries", format, path, entries),
		})
	}

	if recognized == 0 {
		add(report, Check{
			Name:          "release_sbom",
			Status:        StatusWarn,
			Message:       "no readable SBOM files were validated",
			FixSuggestion: "Attach at least one generated SPDX or CycloneDX SBOM before commercial sign-off.",
		})
	}
}

func classifySBOM(doc sbomDocument) (string, int, bool) {
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(doc.SPDXVersion)), "SPDX-") {
		return "SPDX", len(doc.Packages), true
	}
	if strings.EqualFold(strings.TrimSpace(doc.BOMFormat), "CycloneDX") && strings.TrimSpace(doc.SpecVersion) != "" {
		return "CycloneDX", len(doc.Components), true
	}
	return "", 0, false
}

func cleanPathList(paths []string) []string {
	cleaned := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path != "" {
			cleaned = append(cleaned, path)
		}
	}
	return cleaned
}
