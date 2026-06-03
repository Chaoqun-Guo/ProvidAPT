package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/secure"
)

func usage() {
	fmt.Fprint(os.Stderr, `SYNOPSIS
    providapt-verify [OPTIONS]

DESCRIPTION
    Verify the integrity of ProvidAPT's stored provenance data.
    Checks data-file checksums, cryptographic anchors, and detects
    tampering.

OPTIONS
`)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
EXAMPLES
    providapt-verify
        Verify default data directory (/var/lib/providapt/store).

    providapt-verify -data /custom/path
        Verify a non-default data directory.

    providapt-verify -verbose
        Show detailed per-file verification results.

    providapt-verify -output /tmp/report.txt
        Write the verification report to a file.

    providapt-verify -json
        Output verification results as JSON.
`)
}

func main() {
	var (
		dataDir = flag.String("data", "/var/lib/providapt/store", "ProvidAPT data directory")
		verbose = flag.Bool("verbose", false, "Show detailed verification info")
		output  = flag.String("output", "", "Write report to file")
		jsonOut = flag.Bool("json", false, "Output in JSON format")
	)
	flag.Usage = usage
	flag.Parse()

	clioutput.Init(*jsonOut)

	if *dataDir == "" {
		flag.Usage()
		os.Exit(1)
	}

	if _, err := os.Stat(*dataDir); os.IsNotExist(err) {
		clioutput.Fatalf("Data directory not found: %s", *dataDir)
	}

	clioutput.PrintBanner(version.Version)

	// Run verification
	verifier := secure.NewVerifier(*dataDir)
	result, err := verifier.VerifyAll()
	if err != nil {
		clioutput.Fatalf("Verification failed: %v", err)
	}

	// JSON output
	if clioutput.IsJSONMode() {
		type checkItem struct {
			Summary string `json:"summary"`
			Passed  bool   `json:"passed"`
		}
		var checks []checkItem
		for _, line := range result.Errors {
			passed := !containsTampered(line)
			checks = append(checks, checkItem{Summary: line, Passed: passed})
		}
		clioutput.PrintJSON(struct {
			Passed       bool        `json:"passed"`
			FilesChecked int         `json:"files_checked"`
			Tampered     int         `json:"tampered"`
			AnchorsFailed int        `json:"anchors_failed"`
			Checks       []checkItem `json:"checks,omitempty"`
		}{
			Passed:        result.FilesTampered == 0 && result.AnchorsFailed == 0,
			FilesChecked:  result.FilesChecked,
			Tampered:      result.FilesTampered,
			AnchorsFailed: result.AnchorsFailed,
			Checks:        checks,
		})
		os.Exit(0)
	}

	// Text output
	fmt.Println(clioutput.Bold("Verification Results:"))
	fmt.Printf("  Data directory: %s\n\n", *dataDir)

	report := result.TamperReport()
	for _, line := range result.Errors {
		if containsTampered(line) {
			if isPassLine(line) {
				fmt.Printf("  %s  %s\n", clioutput.Okf("✓"), line[2:])
			} else {
				fmt.Printf("  %s  %s\n", clioutput.Errf("✗"), line[2:])
			}
		} else {
			fmt.Printf("  %s\n", line)
		}
	}

	if *verbose && len(result.Errors) > 0 {
		fmt.Println()
		for _, e := range result.Errors {
			if !containsTampered(e) {
				fmt.Printf("  %s\n", e)
			}
		}
	}

	if *output != "" {
		if err := os.WriteFile(*output, []byte(report), 0644); err != nil {
			clioutput.Fatalf("Write report: %v", err)
		}
		fmt.Printf("\nReport saved to: %s\n", clioutput.Okf(*output))
	}

	// Summary
	fmt.Println()
	t := clioutput.NewTable("Check", "Result")
	t.AddRow("Files checked", fmt.Sprintf("%d", result.FilesChecked))
	if result.FilesTampered > 0 {
		t.AddRow("Tampered files", clioutput.Errf(fmt.Sprintf("%d", result.FilesTampered)))
	} else {
		t.AddRow("Tampered files", clioutput.Okf("0"))
	}
	if result.AnchorsFailed > 0 {
		t.AddRow("Anchor failures", clioutput.Errf(fmt.Sprintf("%d", result.AnchorsFailed)))
	} else {
		t.AddRow("Anchor failures", clioutput.Okf("0"))
	}
	t.Render()

	if result.FilesTampered > 0 || result.AnchorsFailed > 0 {
		os.Exit(2)
	}
}

func containsTampered(s string) bool {
	return len(s) >= 8 && (s[:8] == "  ⚠ " || s[:8] == "  ✓ ")
}

func isPassLine(s string) bool {
	return len(s) >= 8 && s[:8] == "  ✓ "
}
