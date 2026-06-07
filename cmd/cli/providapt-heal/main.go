// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/policy/heal"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
)

func usage() {
	fmt.Fprint(os.Stderr, `SYNOPSIS
    providapt-heal [OPTIONS]

DESCRIPTION
    Assess attack impact, roll back malicious changes, and block C2
    communication based on provenance graph analysis.

OPTIONS
`)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
EXAMPLES
    providapt-heal -pid 1234
        Assess impact from process 1234 (dry-run only).

    providapt-heal -pid 1234 -rollback
        Kill the malicious process and quarantine written files.

    providapt-heal -pid 1234 -firewall
        Block C2 IP addresses via iptables/nftables.

    providapt-heal -pid 1234 -rollback -firewall -dry-run=false
        Full active response: rollback + firewall, no dry-run.

    providapt-heal -pid 1234 -depth 10
        Traverse up to 10 hops for blast-radius analysis.

    providapt-heal -pid 1234 -json
        Output impact assessment as JSON.
`)
}

func main() {
	var (
		pid         = flag.Int("pid", 0, "Malicious process PID")
		nodeID      = flag.String("node", "", "Malicious node ID (p:1234)")
		graphPath   = flag.String("graph", "/var/log/providapt/provenance.json", "Provenance graph JSON path")
		dryRun      = flag.Bool("dry-run", true, "Preview actions without executing")
		rollback    = flag.Bool("rollback", false, "Execute rollback (kill procs, quarantine files)")
		firewall    = flag.Bool("firewall", false, "Block C2 IPs via iptables/nftables")
		output      = flag.String("output", "", "Save impact report to file")
		maxDepth    = flag.Int("depth", 5, "Max traversal depth")
		jsonOut     = flag.Bool("json", false, "Output in JSON format")
	)
	flag.Usage = usage
	flag.Parse()

	clioutput.Init(*jsonOut)

	startNode := *nodeID
	if *pid > 0 && startNode == "" {
		startNode = fmt.Sprintf("p:%d", *pid)
	}
	if startNode == "" {
		flag.Usage()
		os.Exit(1)
	}

	clioutput.PrintBanner(version.Version)

	// Load provenance graph
	graph := loadGraph(*graphPath)

	// Phase 1: Impact assessment
	fmt.Println(clioutput.Bold("Phase 1: Impact Assessment"))
	fmt.Printf("  Analyzing impact from %s...\n\n", clioutput.Infof("%s", startNode))

	report := heal.AssessImpact(graph, startNode, *maxDepth)

	if clioutput.IsJSONMode() {
		clioutput.PrintJSON(report)
		return
	}

	printReport(report)

	// Save report
	if *output != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling report: %v\n", err)
			return
		}
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving report: %v\n", err)
			return
		}
		fmt.Printf("\nReport saved: %s\n", clioutput.Okf("%s", *output))
	}

	// Phase 2: Rollback
	if *rollback && report.TotalImpacted > 0 {
		fmt.Println(clioutput.Bold("\nPhase 2: Rollback"))
		cfg := heal.DefaultRollbackConfig()
		cfg.DryRun = *dryRun
		result := heal.Rollback(report, cfg)

		t := clioutput.NewTable("Action", "Count")
		t.AddRow("Processes killed", fmt.Sprintf("%d", result.ProcessesKilled))
		t.AddRow("Files quarantined", fmt.Sprintf("%d", result.FilesQuarantined))
		t.Render()

		for _, e := range result.Errors {
			fmt.Printf("  %s\n", clioutput.Errf("Error: %s", e))
		}
	}

	// Phase 3: Block C2
	if *firewall && len(report.C2Addresses) > 0 {
		fmt.Println(clioutput.Bold("\nPhase 3: C2 Blocking"))
		fwResult := heal.BlockC2IPs(report, *dryRun)

		t := clioutput.NewTable("Item", "Value")
		t.AddRow("Backend", fwResult.Backend)
		t.AddRow("Rules added", fmt.Sprintf("%d", fwResult.RulesAdded))
		t.AddRow("IPs blocked", fmt.Sprintf("%v", fwResult.IPsBlocked))
		t.Render()

		for _, e := range fwResult.Errors {
			fmt.Printf("  %s\n", clioutput.Errf("Error: %s", e))
		}
	}

	if *dryRun && (*rollback || *firewall) {
		fmt.Printf("\n%s\n", clioutput.Warnf("⚠  Dry-run mode — no actions were executed."))
		fmt.Println("  Re-run without -dry-run to apply.")
	}
}

func loadGraph(path string) *provenance.Graph {
	data, err := os.ReadFile(path)
	if err != nil {
		clioutput.Fatalf("Read graph: %v", err)
	}
	graph := provenance.NewGraph()

	var cyto struct {
		Elements []struct {
			Group string `json:"group"`
			Data  struct {
				ID       string `json:"id"`
				Source   string `json:"source"`
				Target   string `json:"target"`
				Label    string `json:"label"`
				NodeType string `json:"type"`
			} `json:"data"`
		} `json:"elements"`
	}
	if err := json.Unmarshal(data, &cyto); err != nil {
		clioutput.Fatalf("Parse graph: %v", err)
	}


	return graph
}

func printReport(r *heal.ImpactReport) {
	// Risk level
	var riskLabel string
	switch {
	case r.TotalImpacted > 10:
		riskLabel = clioutput.Errf("CRITICAL")
	case r.TotalImpacted > 3:
		riskLabel = clioutput.Warnf("HIGH")
	default:
		riskLabel = clioutput.Okf("LOW")
	}

	t := clioutput.NewTable("Metric", "Value")
	t.AddRow("Malicious node", fmt.Sprintf("%s (%s)", r.MaliciousNode, r.MaliciousComm))
	t.AddRow("Impact level", riskLabel)
	t.AddRow("Total impacted", fmt.Sprintf("%d", r.TotalImpacted))
	t.AddRow("Child processes", fmt.Sprintf("%d", len(r.ChildProcesses)))
	t.AddRow("Files written", fmt.Sprintf("%d", len(r.FilesWritten)))
	t.AddRow("C2 addresses", fmt.Sprintf("%d", len(r.C2Addresses)))
	if r.Truncated {
		t.AddRow("⚠  Truncated", fmt.Sprintf("at depth %d", r.MaxDepth))
	}
	t.Render()

	// Child processes detail
	if len(r.ChildProcesses) > 0 {
		fmt.Println()
		ct := clioutput.NewTable("Comm", "PID", "Depth")
		for _, c := range r.ChildProcesses {
			ct.AddRow(c.Comm, fmt.Sprintf("%d", c.PID), fmt.Sprintf("%d", c.Depth))
		}
		ct.Render()
	}

	// Files written
	if len(r.FilesWritten) > 0 {
		fmt.Println()
		ft := clioutput.NewTable("Path", "Action")
		for _, f := range r.FilesWritten {
			ft.AddRow(f.Path, f.Action)
		}
		ft.Render()
	}

	// C2 addresses
	if len(r.C2Addresses) > 0 {
		fmt.Println()
		nt := clioutput.NewTable("C2 Address")
		for _, n := range r.C2Addresses {
			nt.AddRow(n.Address)
		}
		nt.Render()
	}
}
