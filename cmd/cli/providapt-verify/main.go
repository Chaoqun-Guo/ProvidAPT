package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/secure"
)

func main() {
	var (
		dataDir = flag.String("data", "/var/lib/providapt/store", "ProvidAPT data directory")
		verbose = flag.Bool("verbose", false, "Show detailed verification info")
		output  = flag.String("output", "", "Write report to file")
	)
	flag.Parse()

	if *dataDir == "" {
		fmt.Println("Usage: providapt-verify -data /var/lib/providapt/store")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Check if data directory exists
	if _, err := os.Stat(*dataDir); os.IsNotExist(err) {
		log.Fatalf("Data directory not found: %s", *dataDir)
	}

	fmt.Printf("ProvidAPT Integrity Verifier\n")
	fmt.Printf("============================\n\n")
	fmt.Printf("Data directory: %s\n\n", *dataDir)

	// Run verification
	verifier := secure.NewVerifier(*dataDir)
	result, err := verifier.VerifyAll()
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}

	// Print report
	report := result.TamperReport()
	fmt.Print(report)

	if *verbose && len(result.Errors) > 0 {
		fmt.Println("\nDetailed errors:")
		for _, e := range result.Errors {
			if !containsTampered(e) {
				fmt.Printf("  %s\n", e)
			}
		}
	}

	// Write to file if requested
	if *output != "" {
		if err := os.WriteFile(*output, []byte(report), 0644); err != nil {
			log.Fatalf("Write report: %v", err)
		}
		fmt.Printf("\nReport saved to: %s\n", *output)
	}

	// Exit with error if tampering detected
	if result.FilesTampered > 0 || result.AnchorsFailed > 0 {
		os.Exit(2)
	}
}

func containsTampered(s string) bool {
	return len(s) >= 8 && (s[:8] == "  ⚠ " || s[:8] == "  ✓ ")
}
