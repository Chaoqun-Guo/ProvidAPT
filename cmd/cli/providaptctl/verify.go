package main

import (
	"fmt"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/verify"
)

func cmdVerify(cfgPath string, repair bool, dryRun bool) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		clioutput.Fatalf("Config load failed: %v", err)
	}

	storePath := cfg.Output.Dir + "/store"
	if storePath == "/store" {
		storePath = "/var/log/providapt/store"
	}

	if repair {
		clioutput.Printf("%s\n", clioutput.Infof("Running consistency check before repair..."))
	}

	r, err := verify.RunChecks(storePath, dryRun)
	if err != nil {
		clioutput.Fatalf("Verification failed: %v", err)
	}

	if clioutput.IsJSONMode() {
		clioutput.PrintJSON(r)
		return
	}

	fmt.Println(clioutput.Bold("Store Verification Report"))
	fmt.Println()

	t := clioutput.NewTable("Metric", "Value")
	t.AddRow("Store Path", r.StorePath)
	t.AddRow("Nodes", fmt.Sprintf("%d", r.NodeCount))
	t.AddRow("Edges", fmt.Sprintf("%d", r.EdgeCount))
	t.AddRow("Reverse Edges", fmt.Sprintf("%d", r.ReverseCount))
	t.AddRow("Disk Usage", fmt.Sprintf("%d bytes", r.DiskBytes))
	t.AddRow("Issues Found", fmt.Sprintf("%d", r.IssueCount))
	t.AddRow("Repairable", fmt.Sprintf("%d", r.Repairable))
	t.AddRow("Duration", r.Duration.Round(time.Millisecond).String())
	t.Render()
	fmt.Println()

	if r.IssueCount > 0 {
		fmt.Println(clioutput.Bold("Issues:"))
		for i, iss := range r.Issues {
			severity := clioutput.Warnf("WARN")
			if iss.Fixable {
				severity = clioutput.Infof("FIXABLE")
			}
			clioutput.Printf("  %d. [%s] %s: %s\n", i+1, severity, iss.Type, iss.Message)
		}
		fmt.Println()
	}

	if repair && r.Repairable > 0 {
		clioutput.Printf("%s\n", clioutput.Infof("Repairing %d issues...", r.Repairable))
		if err := verify.Repair(r, storePath); err != nil {
			clioutput.Fatalf("Repair failed: %v", err)
		}
		clioutput.Printf("%s\n", clioutput.Okf("Repair complete"))

		// Re-verify
		r2, err := verify.RunChecks(storePath, true)
		if err != nil {
			clioutput.Fatalf("Re-verification failed: %v", err)
		}
		if r2.IssueCount == 0 {
			clioutput.Printf("%s\n", clioutput.Okf("All issues resolved"))
		} else {
			clioutput.Printf("%s\n", clioutput.Warnf("%d issues remaining (not fixable)", r2.IssueCount))
		}
	} else if repair && r.Repairable == 0 {
		if r.IssueCount == 0 {
			clioutput.Printf("%s\n", clioutput.Okf("Store is healthy, no repair needed"))
		} else {
			clioutput.Printf("%s\n", clioutput.Warnf("Issues found but none are repairable"))
		}
	}
}
