package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/client"
)

func main() {
	baseURL := "http://127.0.0.1:8080"
	if len(os.Args) > 1 {
		baseURL = os.Args[1]
	}

	apiClient := client.New(baseURL)

	status, err := apiClient.Status()
	if err != nil {
		log.Fatalf("query status: %v", err)
	}

	fmt.Printf("ProvidAPT status from %s\n", baseURL)
	fmt.Printf("- Status: %s\n", status.Status)
	fmt.Printf("- Nodes: %d\n", status.Nodes)
	fmt.Printf("- Edges: %d\n", status.Edges)
	fmt.Printf("- Health: %s\n", status.Health)
}
