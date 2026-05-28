package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		status  = flag.Bool("status", false, "Query daemon status")
		stop    = flag.Bool("stop", false, "Stop the daemon")
		restart = flag.Bool("restart", false, "Restart the daemon")
		config  = flag.String("config", "/etc/providapt/providapt.toml", "Config file path")
	)
	flag.Parse()

	switch {
	case *status:
		fmt.Println("ProvidAPT: running")
	case *stop:
		fmt.Println("Stopping ProvidAPT...")
	case *restart:
		fmt.Println("Restarting ProvidAPT...")
	default:
		fmt.Printf(`ProvidAPTctl - control the ProvidAPT provenance monitor

Usage:
  providaptctl -status           Query daemon status
  providaptctl -stop             Stop the daemon
  providaptctl -restart          Restart the daemon
  providaptctl -config <path>    Specify config file path

Flags:
`)
		flag.PrintDefaults()
		os.Exit(1)
	}
}
