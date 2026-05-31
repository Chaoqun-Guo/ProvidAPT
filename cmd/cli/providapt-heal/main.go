// ProvidAPT Self-Healing Tool
//
// Assesses attack impact, rolls back changes, and blocks C2
// communication based on provenance graph analysis.
//
// Usage:
//   providapt-heal -pid 1234                         # Assess and heal
//   providapt-heal -pid 1234 -dry-run                # Preview only
//   providapt-heal -pid 1234 -rollback               # Kill + quarantine
//   providapt-heal -pid 1234 -firewall               # Block C2 IPs only
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/policy/heal"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

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
	)
	flag.Parse()

	startNode := *nodeID
	if *pid > 0 && startNode == "" {
		startNode = fmt.Sprintf("p:%d", *pid)
	}
	if startNode == "" {
		fmt.Println("Usage: providapt-heal -pid <pid> [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Load provenance graph from JSON
	graph := loadGraph(*graphPath)

	// Phase 1: Impact assessment
	fmt.Println("ProvidAPT Self-Healing")
	fmt.Println("======================")
	fmt.Printf("\nPhase 1: Assessing impact from %s...\n", startNode)

	report := heal.AssessImpact(graph, startNode, *maxDepth)
	printReport(report)

	// Save report
	if *output != "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(*output, data, 0644)
		fmt.Printf("\nReport saved: %s\n", *output)
	}

	// Phase 2: Rollback
	if *rollback && report.TotalImpacted > 0 {
		fmt.Println("\nPhase 2: Executing rollback...")
		cfg := heal.DefaultRollbackConfig()
		cfg.DryRun = *dryRun
		result := heal.Rollback(report, cfg)

		fmt.Printf("  Processes killed:  %d\n", result.ProcessesKilled)
		fmt.Printf("  Files quarantined: %d\n", result.FilesQuarantined)
		if len(result.Errors) > 0 {
			for _, e := range result.Errors {
				fmt.Printf("  Error: %s\n", e)
			}
		}
	}

	// Phase 3: Block C2
	if *firewall && len(report.C2Addresses) > 0 {
		fmt.Println("\nPhase 3: Blocking C2 communication...")
		fwResult := heal.BlockC2IPs(report, *dryRun)

		fmt.Printf("  Backend: %s\n", fwResult.Backend)
		fmt.Printf("  Rules added: %d\n", fwResult.RulesAdded)
		fmt.Printf("  IPs blocked: %v\n", fwResult.IPsBlocked)
		if len(fwResult.Errors) > 0 {
			for _, e := range fwResult.Errors {
				fmt.Printf("  Error: %s\n", e)
			}
		}
	}

	if *dryRun && (*rollback || *firewall) {
		fmt.Println("\n⚠ Dry-run mode — no actions were executed.")
		fmt.Println("  Re-run without -dry-run to apply.")
	}
}

func loadGraph(path string) *provenance.Graph {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Read graph: %v", err)
	}
	graph := provenance.NewGraph()

	// Parse JSON and feed events
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
		log.Fatalf("Parse graph: %v", err)
	}

	for _, el := range cyto.Elements {
		if el.Group == "nodes" {
			// Node is already in the graph from events
			_ = el.Data.ID
		}
	}

	return graph
}

func printReport(r *heal.ImpactReport) {
	fmt.Printf("\nImpact Report:\n")
	fmt.Printf("  Malicious process: %s (%s)\n", r.MaliciousNode, r.MaliciousComm)
	fmt.Printf("  Child processes:   %d\n", len(r.ChildProcesses))
	for _, c := range r.ChildProcesses {
		fmt.Printf("    - %s (PID %d, depth %d)\n", c.Comm, c.PID, c.Depth)
	}
	fmt.Printf("  Files written:     %d\n", len(r.FilesWritten))
	for _, f := range r.FilesWritten {
		fmt.Printf("    - %s [%s]\n", f.Path, f.Action)
	}
	fmt.Printf("  C2 addresses:      %d\n", len(r.C2Addresses))
	for _, n := range r.C2Addresses {
		fmt.Printf("    - %s\n", n.Address)
	}
	fmt.Printf("  Total impacted:    %d\n", r.TotalImpacted)
	if r.Truncated {
		fmt.Printf("  ⚠  Traversal truncated at depth %d\n", r.MaxDepth)
	}
}
