// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/genrules"
)

func cmdGenRules(outputPath string) {
	if outputPath == "" {
		outputPath = "providapt-alerts.yml"
	}

	clioutput.Printf("%s\n", clioutput.Infof("Generating Prometheus alert rules → %s", outputPath))

	rules := genrules.DefaultRules()
	if err := genrules.WriteFile(outputPath, rules); err != nil {
		clioutput.Fatalf("Failed to write rules: %v", err)
	}

	fmt.Println(clioutput.Bold("Generated Rules"))
	fmt.Println()
	t := clioutput.NewTable("Alert", "Severity", "Expression")
	for _, r := range rules {
		sev := r.Labels["severity"]
		if sev == "" {
			sev = "none"
		}
		expr := r.Expr
		if len(expr) > 60 {
			expr = expr[:57] + "..."
		}
		t.AddRow(r.Alert, sev, expr)
	}
	t.Render()
	fmt.Printf("\n%d rules written to %s\n", len(rules), outputPath)
}
