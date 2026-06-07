// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

// cmdConfigCheck validates the config file and reports any issues.
func cmdConfigCheck(cfgPath string) {
	clioutput.Printf("%s\n", clioutput.Infof("Validating config: %s", cfgPath))

	cfg, err := config.Load(cfgPath)
	if err != nil {
		clioutput.Fatalf("config validation failed: %v", err)
	}

	clioutput.Printf("%s\n", clioutput.Okf("Config is valid"))

	t := clioutput.NewTable("Field", "Value")
	t.AddRow("Config Path", cfgPath)
	t.AddRow("Output Dir", cfg.Output.Dir)
	t.AddRow("Log Level", cfg.Log.Level)
	t.AddRow("REST API", cfg.API.REST)
	t.AddRow("gRPC", cfg.API.GRPC)
	t.AddRow("Auth Enabled", yesNo(cfg.API.AuthEnabled))
	t.AddRow("Rate Limit", formatRateLimit(cfg.API.RateLimitPerSec))
	t.AddRow("CORS Origins", formatStrings(cfg.API.CORSOrigins))
	t.AddRow("TLS Enabled", yesNo(cfg.TLS.Enable))
	t.AddRow("Storage Encrypt", yesNo(cfg.Storage.Encrypt))
	t.Render()
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func formatRateLimit(rate float64) string {
	if rate <= 0 {
		return "disabled"
	}
	return clioutput.Okf("%.0f req/s", rate)
}

func formatStrings(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	result := ""
	for i, v := range s {
		if i > 0 {
			result += ", "
		}
		result += v
	}
	return result
}
